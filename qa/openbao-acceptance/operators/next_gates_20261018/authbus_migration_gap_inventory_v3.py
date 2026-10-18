#!/usr/bin/env python3
"""Read-only follow-up to four exact AuthBus metadata receipts.

The v3 allowlist is derived from four SHA-verified original public receipts.
It is a new version, not a reconstruction of the missing v2 manifest or PLAN. Run with the existing owner on one root-authorized host.
No network, subprocess, SDK, SQL, credential-file payload, service operation,
configuration mutation, or backup extraction is performed. Configuration and
pure-code inputs are projected to approved paths and endpoint host/port fields;
no raw configuration, command arguments, environment values, or quoted code is
emitted. The result never qualifies credentials, restore, cutover, or cleanup.

Use --show-allowlist for an entirely local review without inspecting host paths.
The normal invocation writes one JSON document to stdout and creates no files.
Python 3.9+ standard library only. The caller should impose a 30-second process
limit as well, since an uninterruptible filesystem operation can outlive a
userspace timer.
"""
from __future__ import annotations

import argparse
import contextlib
from datetime import datetime, timezone
import hashlib
import ipaddress
import json
import os
from pathlib import Path, PurePosixPath
import platform
import plistlib
import re
import shlex
import signal
import stat
import time
from urllib.parse import urlsplit


SCHEMA = 'authbus-migration-gap-metadata-v3'
PLAN = json.loads(r'''{"bounds":{"hard_alarm_seconds":24,"maximum_code_bytes":262144,"maximum_config_bytes":2097152,"maximum_depth":2,"maximum_json_depth":32,"maximum_json_nodes":20000,"per_directory_entries":64,"seconds":20,"sqlite_header_bytes":16,"total_directories":96,"total_entries":2048,"total_read_bytes":16777216},"hosts":{"macbook-pro":{"backup_runtime":[{"baseline":{"directory":true,"exists":true,"gid":20,"mode":"0o755","mtime_ns":1792246763991267751,"regular_file":false,"size":512,"symlink":false,"uid":501},"kind":"authbus_runtime_state","path":"/Users/qianqi/.openclaw/authbus"},{"baseline":{"directory":true,"exists":true,"gid":20,"mode":"0o700","mtime_ns":1787725573860262145,"regular_file":false,"size":384,"symlink":false,"uid":501},"kind":"relay_runtime_state","path":"/Users/qianqi/.openclaw/authbus-relay"},{"baseline":{"directory":true,"exists":true,"gid":20,"mode":"0o755","mtime_ns":1791027078796141926,"regular_file":false,"size":128,"symlink":false,"uid":501},"kind":"backup_reference","path":"/Users/qianqi/.openclaw/backups"},{"baseline":{"directory":false,"exists":true,"gid":20,"mode":"0o600","mtime_ns":1781903818380957387,"regular_file":true,"size":33163,"symlink":false,"uid":501},"kind":"backup_reference","path":"/Users/qianqi/.openclaw/openclaw.json.auth-admin2-lastgood-20260620T1143.bak"},{"baseline":{"directory":false,"exists":true,"gid":20,"mode":"0o600","mtime_ns":1788500163590732253,"regular_file":true,"size":34851,"symlink":false,"uid":501},"kind":"backup_reference","path":"/Users/qianqi/.openclaw/openclaw.json.bak"},{"baseline":{"directory":false,"exists":true,"gid":20,"mode":"0o600","mtime_ns":1788499348262568924,"regular_file":true,"size":34851,"symlink":false,"uid":501},"kind":"backup_reference","path":"/Users/qianqi/.openclaw/openclaw.json.bak.1"},{"baseline":{"directory":false,"exists":true,"gid":20,"mode":"0o600","mtime_ns":1788023947176561638,"regular_file":true,"size":33880,"symlink":false,"uid":501},"kind":"backup_reference","path":"/Users/qianqi/.openclaw/openclaw.json.bak.2"},{"baseline":{"directory":false,"exists":true,"gid":20,"mode":"0o600","mtime_ns":1788023829710576265,"regular_file":true,"size":33500,"symlink":false,"uid":501},"kind":"backup_reference","path":"/Users/qianqi/.openclaw/openclaw.json.bak.3"},{"baseline":{"directory":false,"exists":true,"gid":20,"mode":"0o600","mtime_ns":1788023824983162583,"regular_file":true,"size":33102,"symlink":false,"uid":501},"kind":"backup_reference","path":"/Users/qianqi/.openclaw/openclaw.json.bak.4"},{"baseline":{"directory":false,"exists":true,"gid":20,"mode":"0o600","mtime_ns":1781903813181747587,"regular_file":true,"size":33143,"symlink":false,"uid":501},"kind":"backup_reference","path":"/Users/qianqi/.openclaw/openclaw.json.r81-a2a-allow-backup-20260620T051653+0800"}],"baseline_configured_agent_scope_count":5,"binding_files":[{"kind":"caFile","path":"/Users/qianqi/.openclaw/credentials/authbus/ca.crt"},{"kind":"roleIdFile","path":"/Users/qianqi/.openclaw/credentials/authbus/role_id"},{"kind":"secretIdFile","path":"/Users/qianqi/.openclaw/credentials/authbus/secret_id"}],"config":{"path":"/Users/qianqi/.openclaw/openclaw.json","sha256":"ca2dd7d7879fa901dfb24e00837b56a4e0fd230600d7ed1e3086eda194187d4d"},"expected_home":"/Users/qianqi","expected_platform":"Darwin","expected_uid":501,"missing_agents":[],"receipt":{"bytes":24261,"created_at":"2026-10-17T14:19:44.679989+00:00","name":"authbus-current-inventory-r1-macbook-pro.json","sha256":"4445db0b874b12f27a11f2f9dab2d9d261dc6457acf827623f840e1705a560fd"},"relay_dependencies":[{"inspection":"metadata_only","path":"/Users/qianqi/.openclaw/authbus-relay/auth/cliproxy.internal.key"},{"inspection":"metadata_only","path":"/Users/qianqi/.openclaw/authbus-relay/auth/nodes.json"},{"inspection":"pure_code_or_binary_metadata","path":"/Users/qianqi/.openclaw/authbus-relay/bin/authbus-relay-bridge"},{"inspection":"pure_code_or_binary_metadata","path":"/Users/qianqi/.openclaw/authbus-relay/bin/cli-proxy-api"},{"inspection":"pure_code_or_binary_metadata","path":"/Users/qianqi/.openclaw/authbus-relay/bin/egressguard"},{"inspection":"pure_code_or_binary_metadata","path":"/Users/qianqi/.openclaw/authbus-relay/bin/relayfront"},{"inspection":"endpoint_yaml","path":"/Users/qianqi/.openclaw/authbus-relay/config/cliproxy.runtime.yaml"},{"inspection":"endpoint_json","path":"/Users/qianqi/.openclaw/authbus-relay/state/bridge.json"}],"relay_startups":[{"existing_path_references":["/Users/qianqi/.openclaw/authbus-relay/bin/authbus-relay-bridge"],"label":"ai.openclaw.authbus-relay.bridge","path":"/Users/qianqi/Library/LaunchAgents/ai.openclaw.authbus-relay.bridge.plist","sha256":"fa1a74cc6e522bc00d5f64bb48a068d4668549a5800535570eab00b2d6d45630"},{"existing_path_references":["/Users/qianqi/.openclaw/authbus-relay/bin/egressguard"],"label":"ai.openclaw.authbus-relay.egressguard","path":"/Users/qianqi/Library/LaunchAgents/ai.openclaw.authbus-relay.egressguard.plist","sha256":"05df9e3ac02899a9ae37b0bc88784b7df7084cb3d7d1cc89198eff72717775b6"},{"existing_path_references":["/Users/qianqi/.openclaw/authbus-relay/bin/relayfront","/Users/qianqi/.openclaw/authbus-relay/auth/nodes.json","/Users/qianqi/.openclaw/authbus-relay/auth/cliproxy.internal.key","/Users/qianqi/.openclaw/authbus-relay/state/bridge.json"],"label":"ai.openclaw.authbus-relay.front","path":"/Users/qianqi/Library/LaunchAgents/ai.openclaw.authbus-relay.front.plist","sha256":"4a7f95604ff9576fbd274152616be02842c4b90355dfe379b3c9198d0534fc00"},{"existing_path_references":["/Users/qianqi/.openclaw/authbus-relay/bin/cli-proxy-api","/Users/qianqi/.openclaw/authbus-relay/config/cliproxy.runtime.yaml"],"label":"ai.openclaw.authbus-relay.proxy","path":"/Users/qianqi/Library/LaunchAgents/ai.openclaw.authbus-relay.proxy.plist","sha256":"2dcae5db0be14995b5e66b11be9cde1c82114c0417e788222d21dc29ed578a6b"}],"reused_entrypoint_metadata":[{},{"exists":true,"gid":20,"mode":"0o755","mtime_ns":1786452884534499907,"operation_indicators":{"backup_or_restore":false,"cas":false,"inbox":false,"manifest":false,"oauth_refresh":false,"restart":true,"scheduler":false,"writer":false},"path":"/Users/qianqi/.local/bin/openclaw-authbus-restart-when-idle-macos","path_references":[],"sha256":"5a0ba1644dbbf47ad2defb29cddb3ca81cbf5a17b8871fe372a2f833623ae6de","size":800,"uid":501},{"environment_field_names":[],"exists":true,"gid":20,"launch_label":"ai.openclaw.authbus-relay.bridge","launch_program":null,"mode":"0o600","mtime_ns":1786804633572972197,"path":"/Users/qianqi/Library/LaunchAgents/ai.openclaw.authbus-relay.bridge.plist","path_references":["/Users/qianqi/.openclaw/authbus-relay/bin/authbus-relay-bridge"],"sha256":"fa1a74cc6e522bc00d5f64bb48a068d4668549a5800535570eab00b2d6d45630","size":1044,"uid":501},{"environment_field_names":[],"exists":true,"gid":20,"launch_label":"ai.openclaw.authbus-relay.egressguard","launch_program":null,"mode":"0o600","mtime_ns":1786806984111206409,"path":"/Users/qianqi/Library/LaunchAgents/ai.openclaw.authbus-relay.egressguard.plist","path_references":["/Users/qianqi/.openclaw/authbus-relay/bin/egressguard"],"sha256":"05df9e3ac02899a9ae37b0bc88784b7df7084cb3d7d1cc89198eff72717775b6","size":1240,"uid":501},{"environment_field_names":[],"exists":true,"gid":20,"launch_label":"ai.openclaw.authbus-relay.front","launch_program":null,"mode":"0o600","mtime_ns":1786804633573497821,"path":"/Users/qianqi/Library/LaunchAgents/ai.openclaw.authbus-relay.front.plist","path_references":["/Users/qianqi/.openclaw/authbus-relay/bin/relayfront","/Users/qianqi/.openclaw/authbus-relay/auth/nodes.json","/Users/qianqi/.openclaw/authbus-relay/auth/cliproxy.internal.key","/Users/qianqi/.openclaw/authbus-relay/state/bridge.json"],"sha256":"4a7f95604ff9576fbd274152616be02842c4b90355dfe379b3c9198d0534fc00","size":1507,"uid":501},{"environment_field_names":["HOME","HTTPS_PROXY","HTTP_PROXY","MANAGEMENT_PASSWORD","NO_PROXY","PATH"],"exists":true,"gid":20,"launch_label":"ai.openclaw.authbus-relay.proxy","launch_program":null,"mode":"0o600","mtime_ns":1786804633573213988,"path":"/Users/qianqi/Library/LaunchAgents/ai.openclaw.authbus-relay.proxy.plist","path_references":["/Users/qianqi/.openclaw/authbus-relay/bin/cli-proxy-api","/Users/qianqi/.openclaw/authbus-relay/config/cliproxy.runtime.yaml"],"sha256":"2dcae5db0be14995b5e66b11be9cde1c82114c0417e788222d21dc29ed578a6b","size":1480,"uid":501},{"exists":true,"gid":20,"mode":"0o644","mtime_ns":1786452790843154284,"operation_indicators":{"backup_or_restore":false,"cas":false,"inbox":false,"manifest":true,"oauth_refresh":true,"restart":false,"scheduler":false,"writer":false},"path":"/Users/qianqi/.openclaw/extensions/openclaw-authbus/bad-refresh-quarantine.js","path_references":[],"sha256":"916617f296bd2e4b97b240a13418ac6220bb6513a1a0b83f5ee21854edc62286","size":5438,"uid":501},{"exists":true,"gid":20,"mode":"0o644","mtime_ns":1786452790845419721,"operation_indicators":{"backup_or_restore":false,"cas":false,"inbox":false,"manifest":false,"oauth_refresh":false,"restart":false,"scheduler":false,"writer":false},"path":"/Users/qianqi/.openclaw/extensions/openclaw-authbus/codex-client-recycler.js","path_references":[],"sha256":"d3fffe4c401af1dd997017a22930da241d2a4a899c518ce6d25c7047f1b3a13d","size":2120,"uid":501},{"exists":true,"gid":20,"mode":"0o644","mtime_ns":1786452790844162483,"operation_indicators":{"backup_or_restore":true,"cas":true,"inbox":true,"manifest":true,"oauth_refresh":true,"restart":false,"scheduler":true,"writer":true},"path":"/Users/qianqi/.openclaw/extensions/openclaw-authbus/index.js","path_references":["/v1/auth/approle/login"],"sha256":"b19b6a9e7c1d57ccef8d67994ed3421891788ac30a82ff6bad2eef2ef7e30f9b","size":54455,"uid":501},{"exists":true,"gid":20,"mode":"0o644","mtime_ns":1786452790843413115,"operation_indicators":{"backup_or_restore":false,"cas":false,"inbox":false,"manifest":false,"oauth_refresh":false,"restart":false,"scheduler":false,"writer":false},"path":"/Users/qianqi/.openclaw/extensions/openclaw-authbus/lease-assignments.js","path_references":[],"sha256":"24192dc82ddd682e836ea2df717b065b76773c0a1f4b0905f6764e4d498d77e7","size":6932,"uid":501},{"exists":true,"gid":20,"mode":"0o644","mtime_ns":1786452790842751580,"operation_indicators":{"backup_or_restore":false,"cas":false,"inbox":false,"manifest":false,"oauth_refresh":false,"restart":false,"scheduler":true,"writer":true},"path":"/Users/qianqi/.openclaw/extensions/openclaw-authbus/order-policy.js","path_references":[],"sha256":"16bddaa7d18600f9f09dac7b5fb4999a141c86aab1fb15d3e9d6abc24e1cf301","size":7376,"uid":501},{"exists":true,"gid":20,"mode":"0o644","mtime_ns":1786452790844541938,"operation_indicators":{"backup_or_restore":false,"cas":false,"inbox":false,"manifest":false,"oauth_refresh":false,"restart":false,"scheduler":false,"writer":false},"path":"/Users/qianqi/.openclaw/extensions/openclaw-authbus/provider-error-classifier.js","path_references":[],"sha256":"3f9470edea686a0eb46400efecc4c12a284e7fdef018565c34185b0cff102d77","size":4670,"uid":501},{"exists":true,"gid":20,"mode":"0o644","mtime_ns":1786452790844883684,"operation_indicators":{"backup_or_restore":false,"cas":false,"inbox":false,"manifest":true,"oauth_refresh":false,"restart":false,"scheduler":false,"writer":false},"path":"/Users/qianqi/.openclaw/extensions/openclaw-authbus/runtime-refresh-policy.js","path_references":[],"sha256":"8257a6d2ee04868f3a7de5ff8ffaa7fdd3b37bb12a07ac993a3e9c7480c83547","size":956,"uid":501}],"reused_existing_store_metadata":[{"agent_dir":"/Users/qianqi/.openclaw/agents/hepta-backend/agent","directory":{"directory":true,"exists":true,"gid":20,"mode":"0o700","mtime_ns":1791172171566095731,"path":"/Users/qianqi/.openclaw/agents/hepta-backend/agent","regular_file":false,"size":224,"symlink":false,"uid":501},"files":[{"directory":false,"exists":true,"gid":20,"mode":"0o600","mtime_ns":1791169257626839948,"path":"/Users/qianqi/.openclaw/agents/hepta-backend/agent/openclaw-agent.sqlite","regular_file":true,"size":15298560,"symlink":false,"uid":501},{"directory":false,"exists":true,"gid":20,"mode":"0o600","mtime_ns":1791172171566059856,"path":"/Users/qianqi/.openclaw/agents/hepta-backend/agent/openclaw-agent.sqlite-wal","regular_file":true,"size":0,"symlink":false,"uid":501},{"directory":false,"exists":true,"gid":20,"mode":"0o600","mtime_ns":1792238843245564633,"path":"/Users/qianqi/.openclaw/agents/hepta-backend/agent/openclaw-agent.sqlite-shm","regular_file":true,"size":32768,"symlink":false,"uid":501},{"error":"FileNotFoundError","exists":false,"path":"/Users/qianqi/.openclaw/agents/hepta-backend/agent/auth-profiles.json"},{"error":"FileNotFoundError","exists":false,"path":"/Users/qianqi/.openclaw/agents/hepta-backend/agent/auth-state.json"}]},{"agent_dir":"/Users/qianqi/.openclaw/agents/hepta-ui/agent","directory":{"directory":true,"exists":true,"gid":20,"mode":"0o700","mtime_ns":1791172171562659628,"path":"/Users/qianqi/.openclaw/agents/hepta-ui/agent","regular_file":false,"size":160,"symlink":false,"uid":501},"files":[{"directory":false,"exists":true,"gid":20,"mode":"0o600","mtime_ns":1791169257642642317,"path":"/Users/qianqi/.openclaw/agents/hepta-ui/agent/openclaw-agent.sqlite","regular_file":true,"size":209686528,"symlink":false,"uid":501},{"directory":false,"exists":true,"gid":20,"mode":"0o600","mtime_ns":1791172171562624003,"path":"/Users/qianqi/.openclaw/agents/hepta-ui/agent/openclaw-agent.sqlite-wal","regular_file":true,"size":0,"symlink":false,"uid":501},{"directory":false,"exists":true,"gid":20,"mode":"0o600","mtime_ns":1792238843243615208,"path":"/Users/qianqi/.openclaw/agents/hepta-ui/agent/openclaw-agent.sqlite-shm","regular_file":true,"size":32768,"symlink":false,"uid":501},{"error":"FileNotFoundError","exists":false,"path":"/Users/qianqi/.openclaw/agents/hepta-ui/agent/auth-profiles.json"},{"error":"FileNotFoundError","exists":false,"path":"/Users/qianqi/.openclaw/agents/hepta-ui/agent/auth-state.json"}]},{"agent_dir":"/Users/qianqi/.openclaw/agents/hepta/agent","directory":{"directory":true,"exists":true,"gid":20,"mode":"0o700","mtime_ns":1791172171564537408,"path":"/Users/qianqi/.openclaw/agents/hepta/agent","regular_file":false,"size":192,"symlink":false,"uid":501},"files":[{"directory":false,"exists":true,"gid":20,"mode":"0o600","mtime_ns":1791169257599051697,"path":"/Users/qianqi/.openclaw/agents/hepta/agent/openclaw-agent.sqlite","regular_file":true,"size":223727616,"symlink":false,"uid":501},{"directory":false,"exists":true,"gid":20,"mode":"0o600","mtime_ns":1791172171564508699,"path":"/Users/qianqi/.openclaw/agents/hepta/agent/openclaw-agent.sqlite-wal","regular_file":true,"size":0,"symlink":false,"uid":501},{"directory":false,"exists":true,"gid":20,"mode":"0o600","mtime_ns":1792238843244471003,"path":"/Users/qianqi/.openclaw/agents/hepta/agent/openclaw-agent.sqlite-shm","regular_file":true,"size":32768,"symlink":false,"uid":501},{"error":"FileNotFoundError","exists":false,"path":"/Users/qianqi/.openclaw/agents/hepta/agent/auth-profiles.json"},{"error":"FileNotFoundError","exists":false,"path":"/Users/qianqi/.openclaw/agents/hepta/agent/auth-state.json"}]},{"agent_dir":"/Users/qianqi/.openclaw/agents/main/agent","directory":{"directory":true,"exists":true,"gid":20,"mode":"0o700","mtime_ns":1791172174377658146,"path":"/Users/qianqi/.openclaw/agents/main/agent","regular_file":false,"size":1504,"symlink":false,"uid":501},"files":[{"directory":false,"exists":true,"gid":20,"mode":"0o600","mtime_ns":1791172148887603420,"path":"/Users/qianqi/.openclaw/agents/main/agent/openclaw-agent.sqlite","regular_file":true,"size":2469126144,"symlink":false,"uid":501},{"error":"FileNotFoundError","exists":false,"path":"/Users/qianqi/.openclaw/agents/main/agent/openclaw-agent.sqlite-wal"},{"error":"FileNotFoundError","exists":false,"path":"/Users/qianqi/.openclaw/agents/main/agent/openclaw-agent.sqlite-shm"},{"error":"FileNotFoundError","exists":false,"path":"/Users/qianqi/.openclaw/agents/main/agent/auth-profiles.json"},{"error":"FileNotFoundError","exists":false,"path":"/Users/qianqi/.openclaw/agents/main/agent/auth-state.json"}]},{"agent_dir":"/Users/qianqi/.openclaw/agents/trnm/agent","directory":{"directory":true,"exists":true,"gid":20,"mode":"0o700","mtime_ns":1788501096588140174,"path":"/Users/qianqi/.openclaw/agents/trnm/agent","regular_file":false,"size":192,"symlink":false,"uid":501},"files":[{"directory":false,"exists":true,"gid":20,"mode":"0o600","mtime_ns":1788501075770860935,"path":"/Users/qianqi/.openclaw/agents/trnm/agent/openclaw-agent.sqlite","regular_file":true,"size":157589504,"symlink":false,"uid":501},{"directory":false,"exists":true,"gid":20,"mode":"0o600","mtime_ns":1788501096588109840,"path":"/Users/qianqi/.openclaw/agents/trnm/agent/openclaw-agent.sqlite-wal","regular_file":true,"size":0,"symlink":false,"uid":501},{"directory":false,"exists":true,"gid":20,"mode":"0o600","mtime_ns":1792238843242669578,"path":"/Users/qianqi/.openclaw/agents/trnm/agent/openclaw-agent.sqlite-shm","regular_file":true,"size":32768,"symlink":false,"uid":501},{"error":"FileNotFoundError","exists":false,"path":"/Users/qianqi/.openclaw/agents/trnm/agent/auth-profiles.json"},{"error":"FileNotFoundError","exists":false,"path":"/Users/qianqi/.openclaw/agents/trnm/agent/auth-state.json"}]}],"secretrefs":[{"id":"gateway-auth-token","path":"/Users/qianqi/.openclaw/credentials/secretrefs/gateway-auth-token.secret","source":"file"},{"id":"ollama-api-key","path":"/Users/qianqi/.openclaw/credentials/secretrefs/ollama-api-key.secret","source":"file"},{"id":"qwen-portal-api-key","path":"/Users/qianqi/.openclaw/credentials/secretrefs/qwen-portal-api-key.secret","source":"file"},{"id":"google-websearch-api-key","path":"/Users/qianqi/.openclaw/credentials/secretrefs/google-websearch-api-key.secret","source":"file"},{"id":"discord-token","path":"/Users/qianqi/.openclaw/credentials/secretrefs/discord-token.secret","source":"file"},{"id":"feishu-app-secret","path":"/Users/qianqi/.openclaw/credentials/secretrefs/feishu-app-secret.secret","source":"file"},{"id":"google-authprofile-main","path":"/Users/qianqi/.openclaw/credentials/secretrefs/google-authprofile-main.secret","source":"file"},{"id":"google-authprofile-hepta-ui","path":"/Users/qianqi/.openclaw/credentials/secretrefs/google-authprofile-hepta-ui.secret","source":"file"},{"id":"google-authprofile-trnm","path":"/Users/qianqi/.openclaw/credentials/secretrefs/google-authprofile-trnm.secret","source":"file"}]},"main":{"backup_runtime":[{"baseline":{"directory":true,"exists":true,"gid":1000,"mode":"0o755","mtime_ns":1792246782766995965,"regular_file":false,"size":4096,"symlink":false,"uid":1000},"kind":"authbus_runtime_state","path":"/home/qian-qi/.openclaw/authbus"},{"baseline":{"directory":true,"exists":true,"gid":1000,"mode":"0o700","mtime_ns":1791027435646808638,"regular_file":false,"size":98304,"symlink":false,"uid":1000},"kind":"backup_reference","path":"/home/qian-qi/.openclaw/backups"},{"baseline":{"directory":true,"exists":true,"gid":1000,"mode":"0o700","mtime_ns":1790907934440826420,"regular_file":false,"size":4096,"symlink":false,"uid":1000},"kind":"backup_reference","path":"/home/qian-qi/.openclaw/backups/authbus-fallback-reset-20260823T144330+0800"},{"baseline":{"directory":false,"exists":true,"gid":1000,"mode":"0o600","mtime_ns":1781926235200638906,"regular_file":true,"size":19620,"symlink":false,"uid":1000},"kind":"backup_reference","path":"/home/qian-qi/.openclaw/openclaw.json.auth-admin2-lastgood-20260620T1143.bak"},{"baseline":{"directory":false,"exists":true,"gid":1000,"mode":"0o600","mtime_ns":1778058660484985295,"regular_file":true,"size":11417,"symlink":false,"uid":1000},"kind":"backup_reference","path":"/home/qian-qi/.openclaw/openclaw.json.backup-before-telegram-residents-20260506_171100"},{"baseline":{"directory":false,"exists":true,"gid":1000,"mode":"0o600","mtime_ns":1778058676409058058,"regular_file":true,"size":11417,"symlink":false,"uid":1000},"kind":"backup_reference","path":"/home/qian-qi/.openclaw/openclaw.json.backup-before-telegram-residents-20260506_171116"},{"baseline":{"directory":false,"exists":true,"gid":1000,"mode":"0o600","mtime_ns":1791786292622478201,"regular_file":true,"size":25740,"symlink":false,"uid":1000},"kind":"backup_reference","path":"/home/qian-qi/.openclaw/openclaw.json.bak"},{"baseline":{"directory":false,"exists":true,"gid":1000,"mode":"0o600","mtime_ns":1790664862197347019,"regular_file":true,"size":24440,"symlink":false,"uid":1000},"kind":"backup_reference","path":"/home/qian-qi/.openclaw/openclaw.json.bak.1"},{"baseline":{"directory":false,"exists":true,"gid":1000,"mode":"0o600","mtime_ns":1790664844471678242,"regular_file":true,"size":24155,"symlink":false,"uid":1000},"kind":"backup_reference","path":"/home/qian-qi/.openclaw/openclaw.json.bak.2"},{"baseline":{"directory":false,"exists":true,"gid":1000,"mode":"0o600","mtime_ns":1790664734478711637,"regular_file":true,"size":23944,"symlink":false,"uid":1000},"kind":"backup_reference","path":"/home/qian-qi/.openclaw/openclaw.json.bak.3"},{"baseline":{"directory":false,"exists":true,"gid":1000,"mode":"0o600","mtime_ns":1789439516962285661,"regular_file":true,"size":23944,"symlink":false,"uid":1000},"kind":"backup_reference","path":"/home/qian-qi/.openclaw/openclaw.json.bak.4"},{"baseline":{"directory":false,"exists":true,"gid":1000,"mode":"0o600","mtime_ns":1778499097796600997,"regular_file":true,"size":13033,"symlink":false,"uid":1000},"kind":"backup_reference","path":"/home/qian-qi/.openclaw/openclaw.json.pre-restore-telegram4-20260511_193137.bak"},{"baseline":{"directory":false,"exists":true,"gid":1000,"mode":"0o600","mtime_ns":1777794191180281781,"regular_file":true,"size":10453,"symlink":false,"uid":1000},"kind":"backup_reference","path":"/home/qian-qi/.openclaw/openclaw.json.telegram-dns-20260503_154420.bak"},{"baseline":{"directory":false,"exists":true,"gid":1000,"mode":"0o600","mtime_ns":1777792217405549560,"regular_file":true,"size":10307,"symlink":false,"uid":1000},"kind":"backup_reference","path":"/home/qian-qi/.openclaw/openclaw.json.telegram-fix-20260503_154311.bak"},{"baseline":{"directory":false,"exists":true,"gid":1000,"mode":"0o600","mtime_ns":1777794260434595082,"regular_file":true,"size":10552,"symlink":false,"uid":1000},"kind":"backup_reference","path":"/home/qian-qi/.openclaw/openclaw.json.telegram-ipv6-strict-20260503_154947.bak"},{"baseline":{"directory":false,"exists":true,"gid":1000,"mode":"0o600","mtime_ns":1777795064602555510,"regular_file":true,"size":11168,"symlink":false,"uid":1000},"kind":"backup_reference","path":"/home/qian-qi/.openclaw/openclaw.json.telegram-menu-20260503_155952.bak"},{"baseline":{"directory":true,"exists":true,"gid":1000,"mode":"0o775","mtime_ns":1776308981607666079,"regular_file":false,"size":4096,"symlink":false,"uid":1000},"kind":"backup_reference","path":"/home/qian-qi/.openclaw/tmp-antigravity-pairing-backup"}],"baseline_configured_agent_scope_count":8,"binding_files":[{"kind":"caFile","path":"/home/qian-qi/.openclaw/credentials/authbus/ca.crt"},{"kind":"roleIdFile","path":"/home/qian-qi/.openclaw/credentials/authbus/role_id"},{"kind":"secretIdFile","path":"/home/qian-qi/.openclaw/credentials/authbus/secret_id"}],"config":{"path":"/home/qian-qi/.openclaw/openclaw.json","sha256":"791d2d5e7166d02b871a8aa21b0194ca65456c0019757451bfe46d0fe8127d55"},"expected_home":"/home/qian-qi","expected_platform":"Linux","expected_uid":1000,"missing_agents":[{"agent_dir":"/data/toshiba-dev/TrillionniumOS/rootfs/home/qian-qi/.openclaw/agents/trillionnium-os-agent/agent","agent_id":"trillionnium-os-agent","configured_model":{"primary":"openai/gpt-5.6-sol"},"existing_file_references":["/data/toshiba-dev/TrillionniumOS/rootfs/home/qian-qi/.openclaw/agents/trillionnium-os-agent/agent/openclaw-agent.sqlite","/data/toshiba-dev/TrillionniumOS/rootfs/home/qian-qi/.openclaw/agents/trillionnium-os-agent/agent/openclaw-agent.sqlite-wal","/data/toshiba-dev/TrillionniumOS/rootfs/home/qian-qi/.openclaw/agents/trillionnium-os-agent/agent/openclaw-agent.sqlite-shm","/data/toshiba-dev/TrillionniumOS/rootfs/home/qian-qi/.openclaw/agents/trillionnium-os-agent/agent/auth-profiles.json","/data/toshiba-dev/TrillionniumOS/rootfs/home/qian-qi/.openclaw/agents/trillionnium-os-agent/agent/auth-state.json"]},{"agent_dir":"/home/qian-qi/.openclaw/agents/hepta-luna-teacher/agent","agent_id":"hepta-luna-teacher","configured_model":{"primary":"openai/gpt-6-luna"},"existing_file_references":["/home/qian-qi/.openclaw/agents/hepta-luna-teacher/agent/openclaw-agent.sqlite","/home/qian-qi/.openclaw/agents/hepta-luna-teacher/agent/openclaw-agent.sqlite-wal","/home/qian-qi/.openclaw/agents/hepta-luna-teacher/agent/openclaw-agent.sqlite-shm","/home/qian-qi/.openclaw/agents/hepta-luna-teacher/agent/auth-profiles.json","/home/qian-qi/.openclaw/agents/hepta-luna-teacher/agent/auth-state.json"]}],"receipt":{"bytes":29580,"created_at":"2026-10-17T14:19:44.727681+00:00","name":"authbus-current-inventory-r1-main.json","sha256":"a5083d6c99800054eb50155dafe033fd7429fdec48d8b440569eae5678e62452"},"relay_dependencies":[],"relay_startups":[],"reused_entrypoint_metadata":[{},{"exists":true,"gid":1000,"mode":"0o755","mtime_ns":1784394145147097390,"operation_indicators":{"backup_or_restore":false,"cas":false,"inbox":false,"manifest":false,"oauth_refresh":false,"restart":true,"scheduler":false,"writer":false},"path":"/home/qian-qi/.local/bin/openclaw-authbus-accept-after-restart","path_references":["/home/qian-qi/.local/bin/openclaw","/home/qian-qi/.npm-global/bin/openclaw","/home/qian-qi/.openclaw"],"sha256":"02370aa0a042ebea7ac5be5998afa674343abec1d4f8fa53b3d06e5d2c9bbe6b","size":1754,"uid":1000},{"exists":true,"gid":1000,"mode":"0o755","mtime_ns":1784394145149401514,"operation_indicators":{"backup_or_restore":false,"cas":false,"inbox":false,"manifest":false,"oauth_refresh":false,"restart":true,"scheduler":false,"writer":false},"path":"/home/qian-qi/.local/bin/openclaw-authbus-restart-when-idle","path_references":[],"sha256":"a078be050dbb132b3a2a5c3c3d7d29096e32f4aea42612579b5f92c2f1c26be7","size":723,"uid":1000},{"directives":[{"argument_count":0,"directive":"ExecStart","executable":"/home/qian-qi/.local/bin/openclaw-authbus-accept-after-restart","inline_code_present":false,"path_references":["/home/qian-qi/.local/bin/openclaw-authbus-accept-after-restart"]}],"exists":true,"gid":1000,"mode":"0o644","mtime_ns":1784394145151924595,"operation_indicators":{"backup_or_restore":false,"cas":false,"inbox":false,"manifest":false,"oauth_refresh":false,"restart":true,"scheduler":false,"writer":false},"path":"/home/qian-qi/.config/systemd/user/openclaw-authbus-accept-after-restart.service","sha256":"822b44dd4657e91ede788069acb352251369117b90bde6124e150c9442e5e65a","size":198,"uid":1000},{"directives":[{"argument_count":0,"directive":"ExecStart","executable":"/home/qian-qi/.local/bin/openclaw-authbus-restart-when-idle","inline_code_present":false,"path_references":["/home/qian-qi/.local/bin/openclaw-authbus-restart-when-idle"]}],"exists":true,"gid":1000,"mode":"0o644","mtime_ns":1784394145188824833,"operation_indicators":{"backup_or_restore":false,"cas":false,"inbox":false,"manifest":false,"oauth_refresh":false,"restart":true,"scheduler":false,"writer":false},"path":"/home/qian-qi/.config/systemd/user/openclaw-authbus-restart-when-idle.service","sha256":"edfa0b8eb79fc7017265a08b77e14c02688b65b677d25c1d8101dcfa39092d84","size":213,"uid":1000},{"exists":true,"gid":1000,"mode":"0o644","mtime_ns":1786452512686787889,"operation_indicators":{"backup_or_restore":false,"cas":false,"inbox":false,"manifest":true,"oauth_refresh":true,"restart":false,"scheduler":false,"writer":false},"path":"/home/qian-qi/.openclaw/extensions/openclaw-authbus/bad-refresh-quarantine.js","path_references":[],"sha256":"916617f296bd2e4b97b240a13418ac6220bb6513a1a0b83f5ee21854edc62286","size":5438,"uid":1000},{"exists":true,"gid":1000,"mode":"0o644","mtime_ns":1786452512684430722,"operation_indicators":{"backup_or_restore":false,"cas":false,"inbox":false,"manifest":false,"oauth_refresh":false,"restart":false,"scheduler":false,"writer":false},"path":"/home/qian-qi/.openclaw/extensions/openclaw-authbus/codex-client-recycler.js","path_references":[],"sha256":"d3fffe4c401af1dd997017a22930da241d2a4a899c518ce6d25c7047f1b3a13d","size":2120,"uid":1000},{"exists":true,"gid":1000,"mode":"0o644","mtime_ns":1786452512683368018,"operation_indicators":{"backup_or_restore":true,"cas":true,"inbox":true,"manifest":true,"oauth_refresh":true,"restart":false,"scheduler":true,"writer":true},"path":"/home/qian-qi/.openclaw/extensions/openclaw-authbus/index.js","path_references":["/v1/auth/approle/login"],"sha256":"b19b6a9e7c1d57ccef8d67994ed3421891788ac30a82ff6bad2eef2ef7e30f9b","size":54455,"uid":1000},{"exists":true,"gid":1000,"mode":"0o644","mtime_ns":1786452512685265894,"operation_indicators":{"backup_or_restore":false,"cas":false,"inbox":false,"manifest":false,"oauth_refresh":false,"restart":false,"scheduler":false,"writer":false},"path":"/home/qian-qi/.openclaw/extensions/openclaw-authbus/lease-assignments.js","path_references":[],"sha256":"24192dc82ddd682e836ea2df717b065b76773c0a1f4b0905f6764e4d498d77e7","size":6932,"uid":1000},{"exists":true,"gid":1000,"mode":"0o644","mtime_ns":1786452512685695449,"operation_indicators":{"backup_or_restore":false,"cas":false,"inbox":false,"manifest":false,"oauth_refresh":false,"restart":false,"scheduler":true,"writer":true},"path":"/home/qian-qi/.openclaw/extensions/openclaw-authbus/order-policy.js","path_references":[],"sha256":"16bddaa7d18600f9f09dac7b5fb4999a141c86aab1fb15d3e9d6abc24e1cf301","size":7376,"uid":1000},{"exists":true,"gid":1000,"mode":"0o644","mtime_ns":1786452512686376336,"operation_indicators":{"backup_or_restore":false,"cas":false,"inbox":false,"manifest":false,"oauth_refresh":false,"restart":false,"scheduler":false,"writer":false},"path":"/home/qian-qi/.openclaw/extensions/openclaw-authbus/provider-error-classifier.js","path_references":[],"sha256":"3f9470edea686a0eb46400efecc4c12a284e7fdef018565c34185b0cff102d77","size":4670,"uid":1000},{"exists":true,"gid":1000,"mode":"0o644","mtime_ns":1786452512683927002,"operation_indicators":{"backup_or_restore":false,"cas":false,"inbox":false,"manifest":true,"oauth_refresh":false,"restart":false,"scheduler":false,"writer":false},"path":"/home/qian-qi/.openclaw/extensions/openclaw-authbus/runtime-refresh-policy.js","path_references":[],"sha256":"8257a6d2ee04868f3a7de5ff8ffaa7fdd3b37bb12a07ac993a3e9c7480c83547","size":956,"uid":1000}],"reused_existing_store_metadata":[{"agent_dir":"/data/toshiba-dev/TrillionniumOS/rootfs/home/qian-qi/.openclaw/agents/trillionnium-os-agent/agent","directory":{"error":"FileNotFoundError","exists":false,"path":"/data/toshiba-dev/TrillionniumOS/rootfs/home/qian-qi/.openclaw/agents/trillionnium-os-agent/agent"},"files":[{"error":"FileNotFoundError","exists":false,"path":"/data/toshiba-dev/TrillionniumOS/rootfs/home/qian-qi/.openclaw/agents/trillionnium-os-agent/agent/openclaw-agent.sqlite"},{"error":"FileNotFoundError","exists":false,"path":"/data/toshiba-dev/TrillionniumOS/rootfs/home/qian-qi/.openclaw/agents/trillionnium-os-agent/agent/openclaw-agent.sqlite-wal"},{"error":"FileNotFoundError","exists":false,"path":"/data/toshiba-dev/TrillionniumOS/rootfs/home/qian-qi/.openclaw/agents/trillionnium-os-agent/agent/openclaw-agent.sqlite-shm"},{"error":"FileNotFoundError","exists":false,"path":"/data/toshiba-dev/TrillionniumOS/rootfs/home/qian-qi/.openclaw/agents/trillionnium-os-agent/agent/auth-profiles.json"},{"error":"FileNotFoundError","exists":false,"path":"/data/toshiba-dev/TrillionniumOS/rootfs/home/qian-qi/.openclaw/agents/trillionnium-os-agent/agent/auth-state.json"}]},{"agent_dir":"/home/qian-qi/.openclaw/agents/hepta-luna-teacher/agent","directory":{"error":"FileNotFoundError","exists":false,"path":"/home/qian-qi/.openclaw/agents/hepta-luna-teacher/agent"},"files":[{"error":"FileNotFoundError","exists":false,"path":"/home/qian-qi/.openclaw/agents/hepta-luna-teacher/agent/openclaw-agent.sqlite"},{"error":"FileNotFoundError","exists":false,"path":"/home/qian-qi/.openclaw/agents/hepta-luna-teacher/agent/openclaw-agent.sqlite-wal"},{"error":"FileNotFoundError","exists":false,"path":"/home/qian-qi/.openclaw/agents/hepta-luna-teacher/agent/openclaw-agent.sqlite-shm"},{"error":"FileNotFoundError","exists":false,"path":"/home/qian-qi/.openclaw/agents/hepta-luna-teacher/agent/auth-profiles.json"},{"error":"FileNotFoundError","exists":false,"path":"/home/qian-qi/.openclaw/agents/hepta-luna-teacher/agent/auth-state.json"}]},{"agent_dir":"/home/qian-qi/.openclaw/agents/hepta-paper-worker/agent","directory":{"directory":true,"exists":true,"gid":1000,"mode":"0o700","mtime_ns":1790836464044529729,"path":"/home/qian-qi/.openclaw/agents/hepta-paper-worker/agent","regular_file":false,"size":4096,"symlink":false,"uid":1000},"files":[{"directory":false,"exists":true,"gid":1000,"mode":"0o600","mtime_ns":1791168209882041788,"path":"/home/qian-qi/.openclaw/agents/hepta-paper-worker/agent/openclaw-agent.sqlite","regular_file":true,"size":462848,"symlink":false,"uid":1000},{"directory":false,"exists":true,"gid":1000,"mode":"0o600","mtime_ns":1791167457182416647,"path":"/home/qian-qi/.openclaw/agents/hepta-paper-worker/agent/openclaw-agent.sqlite-wal","regular_file":true,"size":24752,"symlink":false,"uid":1000},{"directory":false,"exists":true,"gid":1000,"mode":"0o600","mtime_ns":1791933723318336623,"path":"/home/qian-qi/.openclaw/agents/hepta-paper-worker/agent/openclaw-agent.sqlite-shm","regular_file":true,"size":32768,"symlink":false,"uid":1000},{"directory":false,"exists":true,"gid":1000,"mode":"0o600","mtime_ns":1784251548451482539,"path":"/home/qian-qi/.openclaw/agents/hepta-paper-worker/agent/auth-profiles.json","regular_file":true,"size":11022,"symlink":false,"uid":1000},{"directory":false,"exists":true,"gid":1000,"mode":"0o600","mtime_ns":1784251548452744855,"path":"/home/qian-qi/.openclaw/agents/hepta-paper-worker/agent/auth-state.json","regular_file":true,"size":172,"symlink":false,"uid":1000}]},{"agent_dir":"/home/qian-qi/.openclaw/agents/independent-helper/agent","directory":{"directory":true,"exists":true,"gid":1000,"mode":"0o700","mtime_ns":1790836464022529729,"path":"/home/qian-qi/.openclaw/agents/independent-helper/agent","regular_file":false,"size":4096,"symlink":false,"uid":1000},"files":[{"directory":false,"exists":true,"gid":1000,"mode":"0o600","mtime_ns":1791168209910040756,"path":"/home/qian-qi/.openclaw/agents/independent-helper/agent/openclaw-agent.sqlite","regular_file":true,"size":762224640,"symlink":false,"uid":1000},{"directory":false,"exists":true,"gid":1000,"mode":"0o600","mtime_ns":1791167457207415868,"path":"/home/qian-qi/.openclaw/agents/independent-helper/agent/openclaw-agent.sqlite-wal","regular_file":true,"size":24752,"symlink":false,"uid":1000},{"directory":false,"exists":true,"gid":1000,"mode":"0o600","mtime_ns":1792233869848658882,"path":"/home/qian-qi/.openclaw/agents/independent-helper/agent/openclaw-agent.sqlite-shm","regular_file":true,"size":32768,"symlink":false,"uid":1000},{"directory":false,"exists":true,"gid":1000,"mode":"0o600","mtime_ns":1784251548461490689,"path":"/home/qian-qi/.openclaw/agents/independent-helper/agent/auth-profiles.json","regular_file":true,"size":11022,"symlink":false,"uid":1000},{"directory":false,"exists":true,"gid":1000,"mode":"0o600","mtime_ns":1784251548462222261,"path":"/home/qian-qi/.openclaw/agents/independent-helper/agent/auth-state.json","regular_file":true,"size":674,"symlink":false,"uid":1000}]},{"agent_dir":"/home/qian-qi/.openclaw/agents/main/agent","directory":{"directory":true,"exists":true,"gid":1000,"mode":"0o700","mtime_ns":1791933723283922267,"path":"/home/qian-qi/.openclaw/agents/main/agent","regular_file":false,"size":4096,"symlink":false,"uid":1000},"files":[{"directory":false,"exists":true,"gid":1000,"mode":"0o600","mtime_ns":1792038644538147049,"path":"/home/qian-qi/.openclaw/agents/main/agent/openclaw-agent.sqlite","regular_file":true,"size":2539085824,"symlink":false,"uid":1000},{"directory":false,"exists":true,"gid":1000,"mode":"0o600","mtime_ns":1792037602953315586,"path":"/home/qian-qi/.openclaw/agents/main/agent/openclaw-agent.sqlite-wal","regular_file":true,"size":16512,"symlink":false,"uid":1000},{"directory":false,"exists":true,"gid":1000,"mode":"0o600","mtime_ns":1792038644537147080,"path":"/home/qian-qi/.openclaw/agents/main/agent/openclaw-agent.sqlite-shm","regular_file":true,"size":32768,"symlink":false,"uid":1000},{"error":"FileNotFoundError","exists":false,"path":"/home/qian-qi/.openclaw/agents/main/agent/auth-profiles.json"},{"error":"FileNotFoundError","exists":false,"path":"/home/qian-qi/.openclaw/agents/main/agent/auth-state.json"}]},{"agent_dir":"/home/qian-qi/.openclaw/agents/resident-helper/agent","directory":{"directory":true,"exists":true,"gid":1000,"mode":"0o700","mtime_ns":1791933723287922149,"path":"/home/qian-qi/.openclaw/agents/resident-helper/agent","regular_file":false,"size":4096,"symlink":false,"uid":1000},"files":[{"directory":false,"exists":true,"gid":1000,"mode":"0o600","mtime_ns":1791938624990385290,"path":"/home/qian-qi/.openclaw/agents/resident-helper/agent/openclaw-agent.sqlite","regular_file":true,"size":328282112,"symlink":false,"uid":1000},{"directory":false,"exists":true,"gid":1000,"mode":"0o600","mtime_ns":1791936824989898604,"path":"/home/qian-qi/.openclaw/agents/resident-helper/agent/openclaw-agent.sqlite-wal","regular_file":true,"size":8272,"symlink":false,"uid":1000},{"directory":false,"exists":true,"gid":1000,"mode":"0o600","mtime_ns":1791938624987385522,"path":"/home/qian-qi/.openclaw/agents/resident-helper/agent/openclaw-agent.sqlite-shm","regular_file":true,"size":32768,"symlink":false,"uid":1000},{"directory":false,"exists":true,"gid":1000,"mode":"0o600","mtime_ns":1784251548478522453,"path":"/home/qian-qi/.openclaw/agents/resident-helper/agent/auth-profiles.json","regular_file":true,"size":11022,"symlink":false,"uid":1000},{"directory":false,"exists":true,"gid":1000,"mode":"0o600","mtime_ns":1784251548479988398,"path":"/home/qian-qi/.openclaw/agents/resident-helper/agent/auth-state.json","regular_file":true,"size":674,"symlink":false,"uid":1000}]},{"agent_dir":"/home/qian-qi/.openclaw/agents/telegram-bot-8449317572/agent","directory":{"directory":true,"exists":true,"gid":1000,"mode":"0o700","mtime_ns":1791287949117283696,"path":"/home/qian-qi/.openclaw/agents/telegram-bot-8449317572/agent","regular_file":false,"size":4096,"symlink":false,"uid":1000},"files":[{"directory":false,"exists":true,"gid":1000,"mode":"0o600","mtime_ns":1791314081348078646,"path":"/home/qian-qi/.openclaw/agents/telegram-bot-8449317572/agent/openclaw-agent.sqlite","regular_file":true,"size":395427840,"symlink":false,"uid":1000},{"directory":false,"exists":true,"gid":1000,"mode":"0o600","mtime_ns":1791313390875131651,"path":"/home/qian-qi/.openclaw/agents/telegram-bot-8449317572/agent/openclaw-agent.sqlite-wal","regular_file":true,"size":11053992,"symlink":false,"uid":1000},{"directory":false,"exists":true,"gid":1000,"mode":"0o600","mtime_ns":1791933723313157924,"path":"/home/qian-qi/.openclaw/agents/telegram-bot-8449317572/agent/openclaw-agent.sqlite-shm","regular_file":true,"size":32768,"symlink":false,"uid":1000},{"directory":false,"exists":true,"gid":1000,"mode":"0o600","mtime_ns":1784251548487190742,"path":"/home/qian-qi/.openclaw/agents/telegram-bot-8449317572/agent/auth-profiles.json","regular_file":true,"size":11022,"symlink":false,"uid":1000},{"directory":false,"exists":true,"gid":1000,"mode":"0o600","mtime_ns":1784251548487666650,"path":"/home/qian-qi/.openclaw/agents/telegram-bot-8449317572/agent/auth-state.json","regular_file":true,"size":674,"symlink":false,"uid":1000}]},{"agent_dir":"/home/qian-qi/.openclaw/agents/telegram-bot-8681289317/agent","directory":{"directory":true,"exists":true,"gid":1000,"mode":"0o700","mtime_ns":1788501439385219527,"path":"/home/qian-qi/.openclaw/agents/telegram-bot-8681289317/agent","regular_file":false,"size":4096,"symlink":false,"uid":1000},"files":[{"directory":false,"exists":true,"gid":1000,"mode":"0o600","mtime_ns":1788501430620468891,"path":"/home/qian-qi/.openclaw/agents/telegram-bot-8681289317/agent/openclaw-agent.sqlite","regular_file":true,"size":930381824,"symlink":false,"uid":1000},{"directory":false,"exists":true,"gid":1000,"mode":"0o600","mtime_ns":1788501439385219527,"path":"/home/qian-qi/.openclaw/agents/telegram-bot-8681289317/agent/openclaw-agent.sqlite-wal","regular_file":true,"size":0,"symlink":false,"uid":1000},{"directory":false,"exists":true,"gid":1000,"mode":"0o600","mtime_ns":1791933723303697722,"path":"/home/qian-qi/.openclaw/agents/telegram-bot-8681289317/agent/openclaw-agent.sqlite-shm","regular_file":true,"size":32768,"symlink":false,"uid":1000},{"directory":false,"exists":true,"gid":1000,"mode":"0o600","mtime_ns":1784251548493840134,"path":"/home/qian-qi/.openclaw/agents/telegram-bot-8681289317/agent/auth-profiles.json","regular_file":true,"size":11022,"symlink":false,"uid":1000},{"directory":false,"exists":true,"gid":1000,"mode":"0o600","mtime_ns":1784251548494367517,"path":"/home/qian-qi/.openclaw/agents/telegram-bot-8681289317/agent/auth-state.json","regular_file":true,"size":674,"symlink":false,"uid":1000}]}],"secretrefs":[]},"pocket4":{"backup_runtime":[{"baseline":{"directory":true,"exists":true,"gid":1000,"mode":"0o755","mtime_ns":1792246763011395737,"regular_file":false,"size":4096,"symlink":false,"uid":1000},"kind":"authbus_runtime_state","path":"/home/alex/.openclaw/authbus"},{"baseline":{"directory":true,"exists":true,"gid":1000,"mode":"0o775","mtime_ns":1791027007337568611,"regular_file":false,"size":4096,"symlink":false,"uid":1000},"kind":"backup_reference","path":"/home/alex/.openclaw/backups"},{"baseline":{"directory":false,"exists":true,"gid":1000,"mode":"0o600","mtime_ns":1781868397268248775,"regular_file":true,"size":16963,"symlink":false,"uid":1000},"kind":"backup_reference","path":"/home/alex/.openclaw/openclaw.json.auth-admin2-lastgood-20260620T1143.bak"},{"baseline":{"directory":false,"exists":true,"gid":1000,"mode":"0o600","mtime_ns":1791167446302726287,"regular_file":true,"size":21250,"symlink":false,"uid":1000},"kind":"backup_reference","path":"/home/alex/.openclaw/openclaw.json.bak"},{"baseline":{"directory":false,"exists":true,"gid":1000,"mode":"0o600","mtime_ns":1787839446548740591,"regular_file":true,"size":20713,"symlink":false,"uid":1000},"kind":"backup_reference","path":"/home/alex/.openclaw/openclaw.json.bak.1"},{"baseline":{"directory":false,"exists":true,"gid":1000,"mode":"0o600","mtime_ns":1787747325344951250,"regular_file":true,"size":20617,"symlink":false,"uid":1000},"kind":"backup_reference","path":"/home/alex/.openclaw/openclaw.json.bak.2"},{"baseline":{"directory":false,"exists":true,"gid":1000,"mode":"0o600","mtime_ns":1787004045754766133,"regular_file":true,"size":20617,"symlink":false,"uid":1000},"kind":"backup_reference","path":"/home/alex/.openclaw/openclaw.json.bak.3"},{"baseline":{"directory":false,"exists":true,"gid":1000,"mode":"0o600","mtime_ns":1787004043457424286,"regular_file":true,"size":20618,"symlink":false,"uid":1000},"kind":"backup_reference","path":"/home/alex/.openclaw/openclaw.json.bak.4"}],"baseline_configured_agent_scope_count":2,"binding_files":[{"kind":"caFile","path":"/home/alex/.openclaw/credentials/authbus/ca.crt"},{"kind":"roleIdFile","path":"/home/alex/.openclaw/credentials/authbus/role_id"},{"kind":"secretIdFile","path":"/home/alex/.openclaw/credentials/authbus/secret_id"}],"config":{"path":"/home/alex/.openclaw/openclaw.json","sha256":"3611380b8c77282e785e00e20d9eba8bc8cf0164b3b3f00e2ea5d1f52a441c98"},"expected_home":"/home/alex","expected_platform":"Linux","expected_uid":1000,"missing_agents":[],"receipt":{"bytes":17586,"created_at":"2026-10-17T14:19:45.110303+00:00","name":"authbus-current-inventory-r1-pocket4.json","sha256":"7282f921223de2fb7ea32a7c39298322e65d22350f0a8e871ed87e3f3a8da293"},"relay_dependencies":[],"relay_startups":[],"reused_entrypoint_metadata":[{},{"exists":true,"gid":1000,"mode":"0o755","mtime_ns":1786452667637315129,"operation_indicators":{"backup_or_restore":false,"cas":false,"inbox":false,"manifest":false,"oauth_refresh":false,"restart":true,"scheduler":false,"writer":false},"path":"/home/alex/.local/bin/openclaw-authbus-restart-when-idle","path_references":[],"sha256":"a078be050dbb132b3a2a5c3c3d7d29096e32f4aea42612579b5f92c2f1c26be7","size":723,"uid":1000},{"directives":[{"argument_count":0,"directive":"ExecStart","executable":"/home/alex/.local/bin/openclaw-authbus-restart-when-idle","inline_code_present":false,"path_references":["/home/alex/.local/bin/openclaw-authbus-restart-when-idle"]}],"exists":true,"gid":1000,"mode":"0o644","mtime_ns":1786452667639156392,"operation_indicators":{"backup_or_restore":false,"cas":false,"inbox":false,"manifest":false,"oauth_refresh":false,"restart":true,"scheduler":false,"writer":false},"path":"/home/alex/.config/systemd/user/openclaw-authbus-restart-when-idle.service","sha256":"edfa0b8eb79fc7017265a08b77e14c02688b65b677d25c1d8101dcfa39092d84","size":213,"uid":1000},{"exists":true,"gid":1000,"mode":"0o644","mtime_ns":1786452558848390197,"operation_indicators":{"backup_or_restore":false,"cas":false,"inbox":false,"manifest":true,"oauth_refresh":true,"restart":false,"scheduler":false,"writer":false},"path":"/home/alex/.openclaw/extensions/openclaw-authbus/bad-refresh-quarantine.js","path_references":[],"sha256":"916617f296bd2e4b97b240a13418ac6220bb6513a1a0b83f5ee21854edc62286","size":5438,"uid":1000},{"exists":true,"gid":1000,"mode":"0o644","mtime_ns":1786452558846846407,"operation_indicators":{"backup_or_restore":false,"cas":false,"inbox":false,"manifest":false,"oauth_refresh":false,"restart":false,"scheduler":false,"writer":false},"path":"/home/alex/.openclaw/extensions/openclaw-authbus/codex-client-recycler.js","path_references":[],"sha256":"d3fffe4c401af1dd997017a22930da241d2a4a899c518ce6d25c7047f1b3a13d","size":2120,"uid":1000},{"exists":true,"gid":1000,"mode":"0o664","mtime_ns":1786478900575857271,"operation_indicators":{"backup_or_restore":true,"cas":true,"inbox":true,"manifest":true,"oauth_refresh":true,"restart":false,"scheduler":true,"writer":true},"path":"/home/alex/.openclaw/extensions/openclaw-authbus/index.js","path_references":["/v1/auth/approle/login"],"sha256":"8e10c52df53d6d16d0e5890a6ccdaaff9515469e4419b46270b9bdc62b9be7af","size":54578,"uid":1000},{"exists":true,"gid":1000,"mode":"0o644","mtime_ns":1786452558848657518,"operation_indicators":{"backup_or_restore":false,"cas":false,"inbox":false,"manifest":false,"oauth_refresh":false,"restart":false,"scheduler":false,"writer":false},"path":"/home/alex/.openclaw/extensions/openclaw-authbus/lease-assignments.js","path_references":[],"sha256":"24192dc82ddd682e836ea2df717b065b76773c0a1f4b0905f6764e4d498d77e7","size":6932,"uid":1000},{"exists":true,"gid":1000,"mode":"0o664","mtime_ns":1786478902681916065,"operation_indicators":{"backup_or_restore":false,"cas":false,"inbox":false,"manifest":false,"oauth_refresh":false,"restart":false,"scheduler":true,"writer":true},"path":"/home/alex/.openclaw/extensions/openclaw-authbus/order-policy.js","path_references":[],"sha256":"a1a9923368a1a6bd9adf691aa1beba02d443cf511232e17118c9868160a96e82","size":8506,"uid":1000},{"exists":true,"gid":1000,"mode":"0o644","mtime_ns":1786452558848918046,"operation_indicators":{"backup_or_restore":false,"cas":false,"inbox":false,"manifest":false,"oauth_refresh":false,"restart":false,"scheduler":false,"writer":false},"path":"/home/alex/.openclaw/extensions/openclaw-authbus/provider-error-classifier.js","path_references":[],"sha256":"3f9470edea686a0eb46400efecc4c12a284e7fdef018565c34185b0cff102d77","size":4670,"uid":1000},{"exists":true,"gid":1000,"mode":"0o644","mtime_ns":1786452558847590359,"operation_indicators":{"backup_or_restore":false,"cas":false,"inbox":false,"manifest":true,"oauth_refresh":false,"restart":false,"scheduler":false,"writer":false},"path":"/home/alex/.openclaw/extensions/openclaw-authbus/runtime-refresh-policy.js","path_references":[],"sha256":"8257a6d2ee04868f3a7de5ff8ffaa7fdd3b37bb12a07ac993a3e9c7480c83547","size":956,"uid":1000}],"reused_existing_store_metadata":[{"agent_dir":"/home/alex/.openclaw/agents/main/agent","directory":{"directory":true,"exists":true,"gid":1000,"mode":"0o700","mtime_ns":1792031181785527454,"path":"/home/alex/.openclaw/agents/main/agent","regular_file":false,"size":4096,"symlink":false,"uid":1000},"files":[{"directory":false,"exists":true,"gid":1000,"mode":"0o600","mtime_ns":1792031179561500095,"path":"/home/alex/.openclaw/agents/main/agent/openclaw-agent.sqlite","regular_file":true,"size":399716352,"symlink":false,"uid":1000},{"directory":false,"exists":true,"gid":1000,"mode":"0o600","mtime_ns":1792031181785527454,"path":"/home/alex/.openclaw/agents/main/agent/openclaw-agent.sqlite-wal","regular_file":true,"size":0,"symlink":false,"uid":1000},{"directory":false,"exists":true,"gid":1000,"mode":"0o600","mtime_ns":1792244088121961421,"path":"/home/alex/.openclaw/agents/main/agent/openclaw-agent.sqlite-shm","regular_file":true,"size":32768,"symlink":false,"uid":1000},{"error":"FileNotFoundError","exists":false,"path":"/home/alex/.openclaw/agents/main/agent/auth-profiles.json"},{"error":"FileNotFoundError","exists":false,"path":"/home/alex/.openclaw/agents/main/agent/auth-state.json"}]},{"agent_dir":"/home/alex/.openclaw/agents/tg8687951891/agent","directory":{"directory":true,"exists":true,"gid":1000,"mode":"0o700","mtime_ns":1788501272286727190,"path":"/home/alex/.openclaw/agents/tg8687951891/agent","regular_file":false,"size":4096,"symlink":false,"uid":1000},"files":[{"directory":false,"exists":true,"gid":1000,"mode":"0o600","mtime_ns":1789566180218055328,"path":"/home/alex/.openclaw/agents/tg8687951891/agent/openclaw-agent.sqlite","regular_file":true,"size":28782592,"symlink":false,"uid":1000},{"directory":false,"exists":true,"gid":1000,"mode":"0o600","mtime_ns":1790386258528850938,"path":"/home/alex/.openclaw/agents/tg8687951891/agent/openclaw-agent.sqlite-wal","regular_file":true,"size":0,"symlink":false,"uid":1000},{"directory":false,"exists":true,"gid":1000,"mode":"0o600","mtime_ns":1792238844185899330,"path":"/home/alex/.openclaw/agents/tg8687951891/agent/openclaw-agent.sqlite-shm","regular_file":true,"size":32768,"symlink":false,"uid":1000},{"directory":false,"exists":true,"gid":1000,"mode":"0o600","mtime_ns":1784215612114606472,"path":"/home/alex/.openclaw/agents/tg8687951891/agent/auth-profiles.json","regular_file":true,"size":18334,"symlink":false,"uid":1000},{"directory":false,"exists":true,"gid":1000,"mode":"0o600","mtime_ns":1784215612115606474,"path":"/home/alex/.openclaw/agents/tg8687951891/agent/auth-state.json","regular_file":true,"size":2903,"symlink":false,"uid":1000}]}],"secretrefs":[{"id":"gateway-auth-token","path":"/home/alex/.openclaw/credentials/secretrefs/gateway-auth-token.secret","source":"file"},{"id":"memorysearch-remote-api-key","path":"/home/alex/.openclaw/credentials/secretrefs/memorysearch-remote-api-key.secret","source":"file"},{"id":"google-websearch-api-key","path":"/home/alex/.openclaw/credentials/secretrefs/google-websearch-api-key.secret","source":"file"},{"id":"tg8687951891-model-minimax-api-key","path":"/home/alex/.openclaw/credentials/secretrefs/tg8687951891-model-minimax-api-key.secret","source":"file"},{"id":"tg8687951891-model-minimax-cn-api-key","path":"/home/alex/.openclaw/credentials/secretrefs/tg8687951891-model-minimax-cn-api-key.secret","source":"file"},{"id":"tg8687951891-authprofile-minimax-cn-key","path":"/home/alex/.openclaw/credentials/secretrefs/tg8687951891-authprofile-minimax-cn-key.secret","source":"file"},{"id":"env-gemini-api-key","path":"/home/alex/.openclaw/credentials/secretrefs/env-gemini-api-key.secret","source":"file"},{"id":"env-google-api-key","path":"/home/alex/.openclaw/credentials/secretrefs/env-google-api-key.secret","source":"file"}]},"rog":{"backup_runtime":[{"baseline":{"directory":true,"exists":true,"gid":1000,"mode":"0o755","mtime_ns":1792246763293009994,"regular_file":false,"size":4096,"symlink":false,"uid":1000},"kind":"authbus_runtime_state","path":"/home/qian-qi/.openclaw/authbus"},{"baseline":{"directory":true,"exists":true,"gid":1000,"mode":"0o775","mtime_ns":1791354870948266782,"regular_file":false,"size":4096,"symlink":false,"uid":1000},"kind":"backup_reference","path":"/home/qian-qi/.openclaw/backups"},{"baseline":{"directory":false,"exists":true,"gid":1000,"mode":"0o600","mtime_ns":1791794458536341342,"regular_file":true,"size":27081,"symlink":false,"uid":1000},"kind":"backup_reference","path":"/home/qian-qi/.openclaw/openclaw.json.bak"}],"baseline_configured_agent_scope_count":6,"binding_files":[{"kind":"caFile","path":"/home/qian-qi/.openclaw/credentials/authbus/ca.crt"},{"kind":"roleIdFile","path":"/home/qian-qi/.openclaw/credentials/authbus/role_id"},{"kind":"secretIdFile","path":"/home/qian-qi/.openclaw/credentials/authbus/secret_id"}],"config":{"path":"/home/qian-qi/.openclaw/openclaw.json","sha256":"b9418023037c96a99b3cee9d4a9b570b83f53ea476caf2e6de71837e30155649"},"expected_home":"/home/qian-qi","expected_platform":"Linux","expected_uid":1000,"missing_agents":[],"receipt":{"bytes":22917,"created_at":"2026-10-17T14:19:45.018027+00:00","name":"authbus-current-inventory-r1-rog.json","sha256":"0a10171367de4b7588177f750e65bddef9219a5769615667b356ad0c1602440a"},"relay_dependencies":[],"relay_startups":[],"reused_entrypoint_metadata":[{},{"exists":true,"gid":1000,"mode":"0o755","mtime_ns":1784394145064420517,"operation_indicators":{"backup_or_restore":false,"cas":false,"inbox":false,"manifest":false,"oauth_refresh":false,"restart":true,"scheduler":false,"writer":false},"path":"/home/qian-qi/.local/bin/openclaw-authbus-accept-after-restart","path_references":["/home/qian-qi/.local/bin/openclaw","/home/qian-qi/.npm-global/bin/openclaw","/home/qian-qi/.openclaw"],"sha256":"02370aa0a042ebea7ac5be5998afa674343abec1d4f8fa53b3d06e5d2c9bbe6b","size":1754,"uid":1000},{"exists":true,"gid":1000,"mode":"0o755","mtime_ns":1784394145065354518,"operation_indicators":{"backup_or_restore":false,"cas":false,"inbox":false,"manifest":false,"oauth_refresh":false,"restart":true,"scheduler":false,"writer":false},"path":"/home/qian-qi/.local/bin/openclaw-authbus-restart-when-idle","path_references":[],"sha256":"a078be050dbb132b3a2a5c3c3d7d29096e32f4aea42612579b5f92c2f1c26be7","size":723,"uid":1000},{"directives":[{"argument_count":0,"directive":"ExecStart","executable":"/home/qian-qi/.local/bin/openclaw-authbus-accept-after-restart","inline_code_present":false,"path_references":["/home/qian-qi/.local/bin/openclaw-authbus-accept-after-restart"]}],"exists":true,"gid":1000,"mode":"0o644","mtime_ns":1784394145066079639,"operation_indicators":{"backup_or_restore":false,"cas":false,"inbox":false,"manifest":false,"oauth_refresh":false,"restart":true,"scheduler":false,"writer":false},"path":"/home/qian-qi/.config/systemd/user/openclaw-authbus-accept-after-restart.service","sha256":"822b44dd4657e91ede788069acb352251369117b90bde6124e150c9442e5e65a","size":198,"uid":1000},{"directives":[{"argument_count":0,"directive":"ExecStart","executable":"/home/qian-qi/.local/bin/openclaw-authbus-restart-when-idle","inline_code_present":false,"path_references":["/home/qian-qi/.local/bin/openclaw-authbus-restart-when-idle"]}],"exists":true,"gid":1000,"mode":"0o644","mtime_ns":1784394145066740243,"operation_indicators":{"backup_or_restore":false,"cas":false,"inbox":false,"manifest":false,"oauth_refresh":false,"restart":true,"scheduler":false,"writer":false},"path":"/home/qian-qi/.config/systemd/user/openclaw-authbus-restart-when-idle.service","sha256":"edfa0b8eb79fc7017265a08b77e14c02688b65b677d25c1d8101dcfa39092d84","size":213,"uid":1000},{"exists":true,"gid":1000,"mode":"0o644","mtime_ns":1786452557765425139,"operation_indicators":{"backup_or_restore":false,"cas":false,"inbox":false,"manifest":true,"oauth_refresh":true,"restart":false,"scheduler":false,"writer":false},"path":"/home/qian-qi/.openclaw/extensions/openclaw-authbus/bad-refresh-quarantine.js","path_references":[],"sha256":"916617f296bd2e4b97b240a13418ac6220bb6513a1a0b83f5ee21854edc62286","size":5438,"uid":1000},{"exists":true,"gid":1000,"mode":"0o644","mtime_ns":1786452557765678323,"operation_indicators":{"backup_or_restore":false,"cas":false,"inbox":false,"manifest":false,"oauth_refresh":false,"restart":false,"scheduler":false,"writer":false},"path":"/home/qian-qi/.openclaw/extensions/openclaw-authbus/codex-client-recycler.js","path_references":[],"sha256":"d3fffe4c401af1dd997017a22930da241d2a4a899c518ce6d25c7047f1b3a13d","size":2120,"uid":1000},{"exists":true,"gid":1000,"mode":"0o644","mtime_ns":1786452557765992542,"operation_indicators":{"backup_or_restore":true,"cas":true,"inbox":true,"manifest":true,"oauth_refresh":true,"restart":false,"scheduler":true,"writer":true},"path":"/home/qian-qi/.openclaw/extensions/openclaw-authbus/index.js","path_references":["/v1/auth/approle/login"],"sha256":"b19b6a9e7c1d57ccef8d67994ed3421891788ac30a82ff6bad2eef2ef7e30f9b","size":54455,"uid":1000},{"exists":true,"gid":1000,"mode":"0o644","mtime_ns":1786452557765296368,"operation_indicators":{"backup_or_restore":false,"cas":false,"inbox":false,"manifest":false,"oauth_refresh":false,"restart":false,"scheduler":false,"writer":false},"path":"/home/qian-qi/.openclaw/extensions/openclaw-authbus/lease-assignments.js","path_references":[],"sha256":"24192dc82ddd682e836ea2df717b065b76773c0a1f4b0905f6764e4d498d77e7","size":6932,"uid":1000},{"exists":true,"gid":1000,"mode":"0o644","mtime_ns":1786452557765102455,"operation_indicators":{"backup_or_restore":false,"cas":false,"inbox":false,"manifest":false,"oauth_refresh":false,"restart":false,"scheduler":true,"writer":true},"path":"/home/qian-qi/.openclaw/extensions/openclaw-authbus/order-policy.js","path_references":[],"sha256":"16bddaa7d18600f9f09dac7b5fb4999a141c86aab1fb15d3e9d6abc24e1cf301","size":7376,"uid":1000},{"exists":true,"gid":1000,"mode":"0o644","mtime_ns":1786452557765903455,"operation_indicators":{"backup_or_restore":false,"cas":false,"inbox":false,"manifest":false,"oauth_refresh":false,"restart":false,"scheduler":false,"writer":false},"path":"/home/qian-qi/.openclaw/extensions/openclaw-authbus/provider-error-classifier.js","path_references":[],"sha256":"3f9470edea686a0eb46400efecc4c12a284e7fdef018565c34185b0cff102d77","size":4670,"uid":1000},{"exists":true,"gid":1000,"mode":"0o644","mtime_ns":1786452557765515829,"operation_indicators":{"backup_or_restore":false,"cas":false,"inbox":false,"manifest":true,"oauth_refresh":false,"restart":false,"scheduler":false,"writer":false},"path":"/home/qian-qi/.openclaw/extensions/openclaw-authbus/runtime-refresh-policy.js","path_references":[],"sha256":"8257a6d2ee04868f3a7de5ff8ffaa7fdd3b37bb12a07ac993a3e9c7480c83547","size":956,"uid":1000}],"reused_existing_store_metadata":[{"agent_dir":"/home/qian-qi/.openclaw/agents/azi2/agent","directory":{"directory":true,"exists":true,"gid":1000,"mode":"0o700","mtime_ns":1791961867940777780,"path":"/home/qian-qi/.openclaw/agents/azi2/agent","regular_file":false,"size":4096,"symlink":false,"uid":1000},"files":[{"directory":false,"exists":true,"gid":1000,"mode":"0o600","mtime_ns":1790764123871326138,"path":"/home/qian-qi/.openclaw/agents/azi2/agent/openclaw-agent.sqlite","regular_file":true,"size":405483520,"symlink":false,"uid":1000},{"directory":false,"exists":true,"gid":1000,"mode":"0o600","mtime_ns":1791961867940777780,"path":"/home/qian-qi/.openclaw/agents/azi2/agent/openclaw-agent.sqlite-wal","regular_file":true,"size":0,"symlink":false,"uid":1000},{"directory":false,"exists":true,"gid":1000,"mode":"0o600","mtime_ns":1792238843761834925,"path":"/home/qian-qi/.openclaw/agents/azi2/agent/openclaw-agent.sqlite-shm","regular_file":true,"size":32768,"symlink":false,"uid":1000},{"directory":false,"exists":true,"gid":1000,"mode":"0o600","mtime_ns":1784215556414510584,"path":"/home/qian-qi/.openclaw/agents/azi2/agent/auth-profiles.json","regular_file":true,"size":18334,"symlink":false,"uid":1000},{"directory":false,"exists":true,"gid":1000,"mode":"0o600","mtime_ns":1784215556415264780,"path":"/home/qian-qi/.openclaw/agents/azi2/agent/auth-state.json","regular_file":true,"size":1298,"symlink":false,"uid":1000}]},{"agent_dir":"/home/qian-qi/.openclaw/agents/azi3/agent","directory":{"directory":true,"exists":true,"gid":1000,"mode":"0o700","mtime_ns":1791766135088606703,"path":"/home/qian-qi/.openclaw/agents/azi3/agent","regular_file":false,"size":4096,"symlink":false,"uid":1000},"files":[{"directory":false,"exists":true,"gid":1000,"mode":"0o600","mtime_ns":1790764124195324534,"path":"/home/qian-qi/.openclaw/agents/azi3/agent/openclaw-agent.sqlite","regular_file":true,"size":717037568,"symlink":false,"uid":1000},{"directory":false,"exists":true,"gid":1000,"mode":"0o600","mtime_ns":1791766135088606703,"path":"/home/qian-qi/.openclaw/agents/azi3/agent/openclaw-agent.sqlite-wal","regular_file":true,"size":0,"symlink":false,"uid":1000},{"directory":false,"exists":true,"gid":1000,"mode":"0o600","mtime_ns":1792238843765380430,"path":"/home/qian-qi/.openclaw/agents/azi3/agent/openclaw-agent.sqlite-shm","regular_file":true,"size":32768,"symlink":false,"uid":1000},{"directory":false,"exists":true,"gid":1000,"mode":"0o600","mtime_ns":1784253384058177657,"path":"/home/qian-qi/.openclaw/agents/azi3/agent/auth-profiles.json","regular_file":true,"size":18334,"symlink":false,"uid":1000},{"directory":false,"exists":true,"gid":1000,"mode":"0o600","mtime_ns":1784253384058378093,"path":"/home/qian-qi/.openclaw/agents/azi3/agent/auth-state.json","regular_file":true,"size":1265,"symlink":false,"uid":1000}]},{"agent_dir":"/home/qian-qi/.openclaw/agents/azi4/agent","directory":{"directory":true,"exists":true,"gid":1000,"mode":"0o700","mtime_ns":1792238843767458956,"path":"/home/qian-qi/.openclaw/agents/azi4/agent","regular_file":false,"size":4096,"symlink":false,"uid":1000},"files":[{"directory":false,"exists":true,"gid":1000,"mode":"0o600","mtime_ns":1790764124363323702,"path":"/home/qian-qi/.openclaw/agents/azi4/agent/openclaw-agent.sqlite","regular_file":true,"size":297787392,"symlink":false,"uid":1000},{"directory":false,"exists":true,"gid":1000,"mode":"0o600","mtime_ns":1792238843767458956,"path":"/home/qian-qi/.openclaw/agents/azi4/agent/openclaw-agent.sqlite-wal","regular_file":true,"size":0,"symlink":false,"uid":1000},{"directory":false,"exists":true,"gid":1000,"mode":"0o600","mtime_ns":1792238843768141205,"path":"/home/qian-qi/.openclaw/agents/azi4/agent/openclaw-agent.sqlite-shm","regular_file":true,"size":32768,"symlink":false,"uid":1000},{"directory":false,"exists":true,"gid":1000,"mode":"0o600","mtime_ns":1784682962964032537,"path":"/home/qian-qi/.openclaw/agents/azi4/agent/auth-profiles.json","regular_file":true,"size":20524,"symlink":false,"uid":1000},{"directory":false,"exists":true,"gid":1000,"mode":"0o600","mtime_ns":1784682962966032467,"path":"/home/qian-qi/.openclaw/agents/azi4/agent/auth-state.json","regular_file":true,"size":3682,"symlink":false,"uid":1000}]},{"agent_dir":"/home/qian-qi/.openclaw/agents/azi5/agent","directory":{"directory":true,"exists":true,"gid":1000,"mode":"0o700","mtime_ns":1791107771311692723,"path":"/home/qian-qi/.openclaw/agents/azi5/agent","regular_file":false,"size":4096,"symlink":false,"uid":1000},"files":[{"directory":false,"exists":true,"gid":1000,"mode":"0o600","mtime_ns":1790764124596322548,"path":"/home/qian-qi/.openclaw/agents/azi5/agent/openclaw-agent.sqlite","regular_file":true,"size":394227712,"symlink":false,"uid":1000},{"directory":false,"exists":true,"gid":1000,"mode":"0o600","mtime_ns":1790764131836436476,"path":"/home/qian-qi/.openclaw/agents/azi5/agent/openclaw-agent.sqlite-wal","regular_file":true,"size":0,"symlink":false,"uid":1000},{"directory":false,"exists":true,"gid":1000,"mode":"0o600","mtime_ns":1792238843771078560,"path":"/home/qian-qi/.openclaw/agents/azi5/agent/openclaw-agent.sqlite-shm","regular_file":true,"size":32768,"symlink":false,"uid":1000},{"directory":false,"exists":true,"gid":1000,"mode":"0o600","mtime_ns":1784215556428938585,"path":"/home/qian-qi/.openclaw/agents/azi5/agent/auth-profiles.json","regular_file":true,"size":18334,"symlink":false,"uid":1000},{"directory":false,"exists":true,"gid":1000,"mode":"0o600","mtime_ns":1784215556429149916,"path":"/home/qian-qi/.openclaw/agents/azi5/agent/auth-state.json","regular_file":true,"size":1298,"symlink":false,"uid":1000}]},{"agent_dir":"/home/qian-qi/.openclaw/agents/main/agent","directory":{"directory":true,"exists":true,"gid":1000,"mode":"0o700","mtime_ns":1792049751238999080,"path":"/home/qian-qi/.openclaw/agents/main/agent","regular_file":false,"size":4096,"symlink":false,"uid":1000},"files":[{"directory":false,"exists":true,"gid":1000,"mode":"0o600","mtime_ns":1792246241359496958,"path":"/home/qian-qi/.openclaw/agents/main/agent/openclaw-agent.sqlite","regular_file":true,"size":2573303808,"symlink":false,"uid":1000},{"directory":false,"exists":true,"gid":1000,"mode":"0o600","mtime_ns":1792246209872640152,"path":"/home/qian-qi/.openclaw/agents/main/agent/openclaw-agent.sqlite-wal","regular_file":true,"size":20632,"symlink":false,"uid":1000},{"directory":false,"exists":true,"gid":1000,"mode":"0o600","mtime_ns":1792246209872640152,"path":"/home/qian-qi/.openclaw/agents/main/agent/openclaw-agent.sqlite-shm","regular_file":true,"size":32768,"symlink":false,"uid":1000},{"error":"FileNotFoundError","exists":false,"path":"/home/qian-qi/.openclaw/agents/main/agent/auth-profiles.json"},{"error":"FileNotFoundError","exists":false,"path":"/home/qian-qi/.openclaw/agents/main/agent/auth-state.json"}]},{"agent_dir":"/home/qian-qi/.openclaw/agents/zbj-llm-runtime/agent","directory":{"directory":true,"exists":true,"gid":1000,"mode":"0o700","mtime_ns":1792238843772458947,"path":"/home/qian-qi/.openclaw/agents/zbj-llm-runtime/agent","regular_file":false,"size":4096,"symlink":false,"uid":1000},"files":[{"directory":false,"exists":true,"gid":1000,"mode":"0o600","mtime_ns":1791765816543312028,"path":"/home/qian-qi/.openclaw/agents/zbj-llm-runtime/agent/openclaw-agent.sqlite","regular_file":true,"size":22560768,"symlink":false,"uid":1000},{"directory":false,"exists":true,"gid":1000,"mode":"0o600","mtime_ns":1792238843772458947,"path":"/home/qian-qi/.openclaw/agents/zbj-llm-runtime/agent/openclaw-agent.sqlite-wal","regular_file":true,"size":0,"symlink":false,"uid":1000},{"directory":false,"exists":true,"gid":1000,"mode":"0o600","mtime_ns":1792238843773365035,"path":"/home/qian-qi/.openclaw/agents/zbj-llm-runtime/agent/openclaw-agent.sqlite-shm","regular_file":true,"size":32768,"symlink":false,"uid":1000},{"error":"FileNotFoundError","exists":false,"path":"/home/qian-qi/.openclaw/agents/zbj-llm-runtime/agent/auth-profiles.json"},{"error":"FileNotFoundError","exists":false,"path":"/home/qian-qi/.openclaw/agents/zbj-llm-runtime/agent/auth-state.json"}]}],"secretrefs":[{"id":"gateway-auth-token","path":"/home/qian-qi/.openclaw/credentials/secretrefs/gateway-auth-token.secret","source":"file"},{"id":"zbj-taskflow-webhook","path":"/home/qian-qi/.openclaw/credentials/secretrefs/zbj-taskflow-webhook.secret","source":"file"}]}},"pending_boundaries":[{"basis":"Retained reviewed boundary; no verified owner/path receipt among these four inputs.","id":"x230_owner_source","paths":[],"status":"pending_not_inspected"},{"basis":"A configured provider reference does not inspect its host; no owner/path authority supplied.","id":"ai395_owner_source","paths":[],"status":"pending_not_inspected"},{"basis":"Retained reviewed boundary; no private-CI owner/path authority supplied.","id":"private_ci_client_sources","paths":[],"status":"pending_not_inspected"}],"read_only":true,"reconstruction":"New v3 derived from verified original four-host public receipts; not the missing v2 PLAN or manifest.","schema":"authbus-migration-gap-allowlist-v3","source_receipt_set":{"receipts":[{"bytes":29580,"created_at":"2026-10-17T14:19:44.727681+00:00","host":"main","name":"authbus-current-inventory-r1-main.json","sha256":"a5083d6c99800054eb50155dafe033fd7429fdec48d8b440569eae5678e62452"},{"bytes":24261,"created_at":"2026-10-17T14:19:44.679989+00:00","host":"macbook-pro","name":"authbus-current-inventory-r1-macbook-pro.json","sha256":"4445db0b874b12f27a11f2f9dab2d9d261dc6457acf827623f840e1705a560fd"},{"bytes":22917,"created_at":"2026-10-17T14:19:45.018027+00:00","host":"rog","name":"authbus-current-inventory-r1-rog.json","sha256":"0a10171367de4b7588177f750e65bddef9219a5769615667b356ad0c1602440a"},{"bytes":17586,"created_at":"2026-10-17T14:19:45.110303+00:00","host":"pocket4","name":"authbus-current-inventory-r1-pocket4.json","sha256":"7282f921223de2fb7ea32a7c39298322e65d22350f0a8e871ed87e3f3a8da293"}],"schema":"authbus-migration-gap-source-receipts-v3"},"source_receipt_set_sha256":"bf03a5819e325fac277a2de74768c2639dcb9650cf47285d87e77d26a2f1068c"}''')
LABEL = re.compile(r'[A-Za-z0-9][A-Za-z0-9._:@/+\-]{0,179}\Z')
SAFE_PATH = re.compile(r'/[A-Za-z0-9_./@+ :\-]{1,1535}\Z')
FIELD = re.compile(r'[A-Za-z_][A-Za-z0-9_.\-]{0,95}\Z')
SENSITIVE_DIRS = {'auth', 'credentials', 'keys', 'secrets', 'tokens', '.ssh', '.aws'}
SENSITIVE_FILES = re.compile(r'(?:^|[._\-])(?:secret|token|password|passwd|private|credential|role[_-]?id|secret[_-]?id|api[_-]?key)(?:[._\-]|$)', re.I)
FORBIDDEN_CONTENT_SUFFIXES = {'.secret', '.key', '.pem', '.p12', '.pfx'}
ENDPOINT_FIELDS = {
    'address', 'addr', 'url', 'baseurl', 'base_url', 'base-url', 'endpoint',
    'listen', 'listen_addr', 'listen_address', 'listen-address', 'bind',
    'upstream', 'upstream_url', 'upstream-url', 'upstream_address',
    'backend', 'backend_url', 'backend-url', 'target', 'target_url',
    'proxy', 'proxy_url', 'proxy-url', 'http_proxy', 'https_proxy', 'all_proxy',
    'downstream', 'downstream_url', 'downstream-url', 'server_url',
}
HOST_FIELDS = {'host', 'hostname', 'bind_host', 'listen_host', 'upstream_host', 'backend_host'}
PORT_FIELDS = {'port', 'listen_port', 'listen-port', 'bind_port', 'upstream_port', 'backend_port'}
PATH_FIELDS = {'config', 'config_file', 'config-file', 'state_file', 'state-file',
               'ca_file', 'ca-file', 'tls_ca_file', 'tls_cert_file', 'tls_key_file',
               'auth_file', 'auth-file', 'key_file', 'key-file', 'data_dir', 'storage_path',
               'environmentfile', 'workingdirectory'}
ENDPOINT_CONTAINERS = {'relay', 'bridge', 'front', 'proxy', 'server', 'servers', 'client', 'clients',
                       'backends', 'upstreams', 'downstreams', 'listener', 'listeners', 'endpoints',
                       'routing', 'routes', 'config', 'network', 'status', 'transport'}
SENSITIVE_CONTAINERS = re.compile(r'auth|credential|token|secret|password|api.?key|private.?key|header|cookie|certificate', re.I)


def sha(payload):
    return hashlib.sha256(payload).hexdigest()


def safe_label(value):
    return value if isinstance(value, str) and LABEL.fullmatch(value) else None


def safe_path(value, home):
    if not isinstance(value, str):
        return None
    for prefix in ('${HOME}/', '$HOME/', '%h/', '~/'):
        if value.startswith(prefix):
            value = home + '/' + value[len(prefix):]
            break
    if not SAFE_PATH.fullmatch(value):
        return None
    p = PurePosixPath(value)
    if '..' in p.parts or str(p) != value or value.startswith('//'):
        return None
    return value


def safe_field(value):
    return value if isinstance(value, str) and FIELD.fullmatch(value) else '<omitted-field>'


def endpoint(value):
    """Return only endpoint metadata; userinfo, path, query and fragment vanish."""
    if not isinstance(value, str) or not value or len(value) > 4096:
        return None
    try:
        text = value.strip()
        if any(ord(c) < 32 for c in text):
            return None
        parsed = urlsplit(text if '://' in text else '//' + text)
        if parsed.scheme and parsed.scheme.lower() not in ('http', 'https', 'socks', 'socks5', 'tcp', 'tls'):
            return None
        host = parsed.hostname
        if not host or len(host) > 253:
            return None
        try:
            ipaddress.ip_address(host)
        except ValueError:
            if not all(re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?', part)
                       for part in host.rstrip('.').split('.')):
                return None
        port = parsed.port
        if port is not None and not 0 < port < 65536:
            return None
        return {'scheme': parsed.scheme.lower() or None, 'host': host, 'port': port,
                'userinfo_omitted': bool(parsed.username is not None or parsed.password is not None),
                'path_query_fragment_omitted': bool(parsed.path or parsed.query or parsed.fragment),
                'references_j3160': host.lower() in ('j3160', '100.66.117.33'),
                'references_uninspected_host': host.lower() in ('x230', 'ai395')}
    except (ValueError, UnicodeError):
        return None


def metadata_values(value):
    mode = stat.S_IMODE(value.st_mode)
    return {'exists': True, 'uid': value.st_uid, 'gid': value.st_gid,
            'mode': oct(mode), 'size': value.st_size, 'mtime_ns': value.st_mtime_ns, 'ctime_ns': value.st_ctime_ns,
            'dev': value.st_dev, 'inode': value.st_ino, 'nlink': value.st_nlink,
            'symlink': stat.S_ISLNK(value.st_mode), 'directory': stat.S_ISDIR(value.st_mode),
            'regular_file': stat.S_ISREG(value.st_mode),
            'group_or_other_writable': bool(mode & 0o022),
            'group_or_other_access': bool(mode & 0o077)}


def file_stamp(value):
    return (value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns, value.st_ctime_ns)


class Refused(Exception):
    pass


class BudgetExceeded(Exception):
    pass


class Budget:
    def __init__(self, bounds):
        self.bounds = bounds
        self.started = time.monotonic()
        self.deadline = self.started + bounds['seconds']
        self.bytes_read = 0
        self.entries = 0
        self.directories = 0
        self.hits = set()

    def gate(self):
        if time.monotonic() >= self.deadline:
            self.hits.add('original_time_budget')
            raise BudgetExceeded('original_time_budget')

    def read_bound(self, count):
        # os.read already returned: account actual bytes even across the deadline.
        self.bytes_read += count
        if self.bytes_read > self.bounds['total_read_bytes']:
            self.hits.add('total_read_bytes')
            raise BudgetExceeded('total_read_bytes')
        self.gate()


class NoFollowFilesystem:
    """All path traversal uses held, no-follow parent directory descriptors."""
    def __init__(self, selected, budget):
        self.selected = selected
        self.budget = budget
        self.tree_roots = {v['path'] for v in selected['backup_runtime']}
        self.exact = {selected['config']['path']}
        for key in ('secretrefs', 'backup_runtime', 'binding_files', 'relay_startups', 'relay_dependencies'):
            self.exact.update(v['path'] for v in selected[key])
        for item in selected['missing_agents']:
            self.exact.add(item['agent_dir'])
            self.exact.update(item['existing_file_references'])
        self.never_read = {v['path'] for v in selected['secretrefs'] + selected['binding_files']}
        self.never_read.update(v['path'] for v in selected['relay_dependencies']
                               if v['inspection'] == 'metadata_only')
        self.content_reads = []
        self.read_metadata = {}

    def allowed(self, path):
        if safe_path(path, self.selected['expected_home']) != path:
            return False
        if re.search(r'hepta[-_]?trader', path, re.I):
            return False
        if path in self.exact:
            return True
        p = PurePosixPath(path)
        return any(p.is_relative_to(PurePosixPath(root)) and
                   len(p.relative_to(PurePosixPath(root)).parts) <= self.budget.bounds['maximum_depth']
                   for root in self.tree_roots)

    @contextlib.contextmanager
    def parent(self, path):
        self.budget.gate()
        if not self.allowed(path):
            raise Refused('path_not_allowlisted')
        parts = PurePosixPath(path).parts
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
        fd = os.open('/', flags)
        chain = [{'path': '/', **metadata_values(os.fstat(fd))}]
        try:
            prefix = ''
            for name in parts[1:-1]:
                self.budget.gate()
                child = os.open(name, flags, dir_fd=fd)
                os.close(fd)
                fd = child
                prefix += '/' + name
                chain.append({'path': prefix, **metadata_values(os.fstat(fd))})
            self.budget.gate()
            yield fd, parts[-1], chain
            self.budget.gate()
        finally:
            os.close(fd)

    def metadata(self, path, parents=False):
        out = {'path': path, 'contents_read': False}
        try:
            with self.parent(path) as (fd, name, chain):
                value = os.stat(name, dir_fd=fd, follow_symlinks=False)
                self.budget.gate()
                out.update(metadata_values(value))
                if parents:
                    out['parent_chain'] = chain
        except (OSError, Refused, BudgetExceeded) as exc:
            out.update(exists=False if isinstance(exc, FileNotFoundError) else None,
                       scan_error=type(exc).__name__)
            if isinstance(exc, (Refused, BudgetExceeded)):
                out['reason'] = exc.args[0]
        return out

    def read(self, path, maximum, profile, prefix=False):
        if path in self.never_read or '/auth/' in path or '/credentials/' in path:
            raise Refused('credential_file_content_prohibited')
        if SENSITIVE_FILES.search(PurePosixPath(path).name) or PurePosixPath(path).suffix.lower() in FORBIDDEN_CONTENT_SUFFIXES:
            raise Refused('sensitive_file_content_prohibited')
        with self.parent(path) as (parent, name, _):
            self.budget.gate()
            old = os.stat(name, dir_fd=parent, follow_symlinks=False)
            self.budget.gate()
            if not stat.S_ISREG(old.st_mode) or (not prefix and old.st_size > maximum):
                raise Refused('bounded_regular_file_required')
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK, dir_fd=parent)
            try:
                before = os.fstat(fd)
                self.budget.gate()
                if file_stamp(old) != file_stamp(before) or not stat.S_ISREG(before.st_mode):
                    raise Refused('file_changed_before_read')
                chunks, count, interrupts = [], 0, 0
                while count < maximum if prefix else True:
                    self.budget.gate()
                    bound = min(65536, maximum - count if prefix else maximum + 1 - count)
                    remaining = self.budget.bounds['total_read_bytes'] - self.budget.bytes_read
                    if remaining <= 0:
                        self.budget.hits.add('total_read_bytes')
                        raise BudgetExceeded('total_read_bytes')
                    bound = min(bound, remaining)
                    try:
                        block = os.read(fd, bound)
                    except InterruptedError:
                        interrupts += 1
                        if interrupts > 64:
                            raise Refused('interrupted_read_bound')
                        continue
                    self.budget.read_bound(len(block))
                    if not block:
                        break
                    chunks.append(block)
                    count += len(block)
                    if count > maximum:
                        raise Refused('file_size_bound')
                after = os.fstat(fd)
                named_after = os.stat(name, dir_fd=parent, follow_symlinks=False)
                self.budget.gate()
                if file_stamp(before) != file_stamp(after) or file_stamp(before) != file_stamp(named_after):
                    raise Refused('file_changed_during_read')
                result = b''.join(chunks)
                if not prefix and len(result) != before.st_size:
                    raise Refused('file_length_changed')
                self.content_reads.append({'path': path, 'profile': profile, 'bytes': len(result),
                                           'header_only': prefix})
                self.read_metadata[path] = metadata_values(before)
                return result
            finally:
                os.close(fd)

    def children(self, path):
        self.budget.gate()
        if self.budget.directories >= self.budget.bounds['total_directories']:
            self.budget.hits.add('total_directories')
            raise BudgetExceeded('total_directories')
        result, bound_hit = [], False
        with self.parent(path) as (parent, name, _):
            fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
            try:
                self.budget.directories += 1
                with os.scandir(fd) as it:
                    for item in it:
                        self.budget.gate()
                        if len(result) >= self.budget.bounds['per_directory_entries']:
                            bound_hit = True
                            self.budget.hits.add('per_directory_entries')
                            break
                        if self.budget.entries >= self.budget.bounds['total_entries']:
                            bound_hit = True
                            self.budget.hits.add('total_entries')
                            break
                        self.budget.entries += 1
                        candidate = path + '/' + item.name
                        if not self.allowed(candidate):
                            result.append({'path': None, 'entry_name_sha256': sha(item.name.encode()),
                                           'contents_read': False, 'scan_error': 'Refused',
                                           'reason': 'unsafe_name_or_excluded_scope'})
                            continue
                        value = os.stat(item.name, dir_fd=fd, follow_symlinks=False)
                        result.append({'path': candidate, 'contents_read': False, **metadata_values(value)})
            finally:
                os.close(fd)
        return sorted(result, key=lambda x: x.get('path') or x.get('entry_name_sha256')), bound_hit


def bounded_json(raw, budget):
    value = json.loads(raw)
    stack, nodes = [(value, 0)], 0
    while stack:
        item, depth = stack.pop()
        budget.gate()
        nodes += 1
        if nodes > budget.bounds['maximum_json_nodes'] or depth > budget.bounds['maximum_json_depth']:
            raise Refused('json_structure_bound')
        if isinstance(item, dict):
            stack.extend((v, depth + 1) for v in item.values())
        elif isinstance(item, list):
            stack.extend((v, depth + 1) for v in item)
    return value


def direction(field):
    lowered = field.lower().replace('-', '_')
    if 'downstream' in lowered:
        return 'configured_downstream'
    if any(v in lowered for v in ('upstream', 'backend', 'target', 'proxy')):
        return 'configured_upstream_or_proxy'
    if any(v in lowered for v in ('listen', 'bind')):
        return 'configured_listener'
    return 'configured_endpoint_direction_unresolved'


def endpoint_projection(value, budget, home):
    result, paths = [], []
    def visit(item, pointer, depth=0):
        budget.gate()
        if depth > budget.bounds['maximum_json_depth']:
            raise Refused('json_structure_bound')
        if isinstance(item, dict):
            for key, val in item.items():
                lowered = key.lower() if isinstance(key, str) else ''
                field = safe_field(key) if lowered in ENDPOINT_FIELDS | HOST_FIELDS | PORT_FIELDS | PATH_FIELDS | ENDPOINT_CONTAINERS else '<unselected-container>'
                location = pointer + '/' + field
                if lowered in ENDPOINT_FIELDS:
                    ep = endpoint(val)
                    if ep:
                        result.append({'field': location, 'direction': direction(lowered), 'endpoint': ep})
                elif lowered in HOST_FIELDS:
                    ep = endpoint(val)
                    if ep:
                        for p in PORT_FIELDS:
                            port = item.get(p)
                            if isinstance(port, int) and not isinstance(port, bool) and 0 < port < 65536:
                                ep['port'] = port
                                break
                        result.append({'field': location, 'direction': direction(lowered), 'endpoint': ep})
                elif lowered in PORT_FIELDS and isinstance(val, int) and not isinstance(val, bool) and 0 < val < 65536:
                    result.append({'field': location, 'direction': direction(lowered),
                                   'endpoint': {'host': None, 'port': val, 'scheme': None}})
                elif lowered in PATH_FIELDS:
                    ref = safe_path(val, home)
                    if ref:
                        paths.append({'field': location, 'path': ref, 'followed': False})
                if isinstance(val, (dict, list)) and not SENSITIVE_CONTAINERS.search(lowered):
                    visit(val, location, depth + 1)
        elif isinstance(item, list):
            for i, val in enumerate(item):
                if isinstance(val, (dict, list)):
                    visit(val, pointer + '/' + str(i), depth + 1)
    visit(value, '')
    return {'endpoints': result[:128], 'path_references': paths[:128],
            'projection_bound_hit': len(result) > 128 or len(paths) > 128,
            'runtime_consumption_verified': False}


def openclaw_projection(config, selected, budget):
    if not isinstance(config, dict):
        raise Refused('configuration_object_required')
    plugins = config.get('plugins', {})
    entries = plugins.get('entries', {}) if isinstance(plugins, dict) else {}
    entry = entries.get('openclaw-authbus', {}) if isinstance(entries, dict) else {}
    auth = entry.get('config', {}) if isinstance(entry, dict) else {}
    auth = auth if isinstance(auth, dict) else {}
    out = {'authbus': {'enabled': entry.get('enabled') is True if isinstance(entry, dict) else False,
                      'endpoint': endpoint(auth.get('address')),
                      'host_id': safe_label(auth.get('hostId')),
                      'binding_paths': {k: safe_path(auth.get(k), selected['expected_home'])
                                        for k in ('caFile', 'roleIdFile', 'secretIdFile')}},
           'agents': [], 'known_secret_providers': [], 'secretref_consumer_locations': [],
           'provider_endpoints': []}
    agents = config.get('agents', {})
    agents = agents if isinstance(agents, dict) else {}
    agent_list = agents.get('list', [])
    for i, val in enumerate(agent_list[:64] if isinstance(agent_list, list) else []):
        if not isinstance(val, dict):
            continue
        model = val.get('model')
        primary = model.get('primary') if isinstance(model, dict) else model
        out['agents'].append({'id': safe_label(val.get('id')), 'config_pointer': '/agents/list/' + str(i),
                              'declared_agent_dir': safe_path(val.get('agentDir'), selected['expected_home']),
                              'agent_dir_explicit': isinstance(val.get('agentDir'), str),
                              'model_primary': safe_label(primary)})
    secrets = config.get('secrets', {})
    providers = secrets.get('providers', {}) if isinstance(secrets, dict) else {}
    providers = providers if isinstance(providers, dict) else {}
    known_ids = {v['id'] for v in selected['secretrefs']}
    for expected in selected['secretrefs']:
        val = providers.get(expected['id'])
        present = isinstance(val, dict)
        val = val if present else {}
        actual_path = safe_path(val.get('path'), selected['expected_home'])
        out['known_secret_providers'].append({'id': expected['id'], 'present': present,
                    'source': safe_label(val.get('source')), 'path': actual_path,
                    'original_path_matches': actual_path == expected['path'],
                    'new_reference_followed': False})
    models = config.get('models', {})
    model_providers = models.get('providers', {}) if isinstance(models, dict) else {}
    for name, val in list(model_providers.items())[:64] if isinstance(model_providers, dict) else []:
        if isinstance(val, dict):
            out['provider_endpoints'].append({'provider': safe_label(name), 'endpoint': endpoint(val.get('baseUrl'))})
    stack = [(config, '')]
    while stack:
        item, pointer = stack.pop()
        budget.gate()
        if isinstance(item, dict):
            provider = item.get('provider')
            if item.get('source') == 'file' and isinstance(provider, str) and provider in known_ids:
                out['secretref_consumer_locations'].append({'provider': provider,
                                                            'config_pointer': pointer,
                                                            'credential_selector_omitted': True})
            for key, val in item.items():
                if isinstance(val, (dict, list)):
                    stack.append((val, pointer + '/' + safe_field(key)))
        elif isinstance(item, list):
            stack.extend((v, pointer + '/' + str(i)) for i, v in enumerate(item) if isinstance(v, (dict, list)))
    out['secretref_consumer_locations'] = out['secretref_consumer_locations'][:256]
    out['all_secretref_providers_in_existing_allowlist'] = all(k in known_ids for k in providers)
    return out


def text_endpoint_projection(raw, budget, home):
    text = raw.decode('utf-8')
    endpoints, paths, commands = [], [], []
    # Only approved assignment field names are projected. No arbitrary scalar,
    # source quote, command, password, API key or environment value is returned.
    for line in text.splitlines()[:8192]:
        budget.gate()
        command = re.match(r'^\s*(ExecStart(?:Pre|Post)?|ExecStop)\s*=\s*(.{1,16384})$', line)
        if command:
            try:
                argv = shlex.split(command.group(2))[:64]
            except ValueError:
                commands.append({'field': command.group(1), 'parse_error': True})
                continue
            executable = safe_path(argv[0].lstrip('-@:+!'), home) if argv else None
            refs = []
            for i, arg in enumerate(argv):
                name, equal, val = arg.lstrip('-').partition('=')
                if name.lower() not in PATH_FIELDS:
                    continue
                ref = safe_path(val if equal else argv[i + 1] if i + 1 < len(argv) else None, home)
                if ref:
                    refs.append({'field': name, 'path': ref, 'followed': False})
            commands.append({'field': command.group(1), 'executable': executable,
                             'path_references': refs,
                             'inline_code_present': any(v in ('-c', '-e', '--eval') for v in argv),
                             'command_executed': False})
            continue
        match = re.match(r'^\s*(?:-\s+)?(?:export\s+)?["\']?([A-Za-z_][A-Za-z0-9_-]{0,95})["\']?\s*[:=]\s*(.*?)\s*$', line)
        if not match:
            continue
        key, val = match.groups()
        lowered = key.lower()
        if lowered not in ENDPOINT_FIELDS | HOST_FIELDS | PORT_FIELDS | PATH_FIELDS:
            continue
        val = val.strip().strip(',;').strip('"\'')
        if lowered in ENDPOINT_FIELDS | HOST_FIELDS:
            ep = endpoint(val)
            if ep:
                endpoints.append({'field': key, 'direction': direction(key), 'endpoint': ep})
        elif lowered in PORT_FIELDS and val.isdigit() and 0 < int(val) < 65536:
            endpoints.append({'field': key, 'direction': direction(key),
                              'endpoint': {'host': None, 'port': int(val), 'scheme': None}})
        elif lowered in PATH_FIELDS:
            ref = safe_path(val, home)
            if ref:
                paths.append({'field': key, 'path': ref, 'followed': False})
    return {'endpoints': endpoints[:128], 'path_references': paths[:128], 'command_entrypoints': commands[:32],
            'projection_bound_hit': len(endpoints) > 128 or len(paths) > 128 or len(commands) > 32,
            'mentions_j3160': bool(re.search(r'j3160|100\.66\.117\.33', text, re.I)),
            'runtime_consumption_verified': False}


def plist_projection(raw, selected, budget):
    value = plistlib.loads(raw)
    if not isinstance(value, dict):
        raise Refused('plist_object_required')
    args = value.get('ProgramArguments', [])
    args = args[:64] if isinstance(args, list) else []
    known_paths = {v['path'] for v in selected['relay_dependencies']}
    paths = {v for v in args if isinstance(v, str) and v in known_paths}
    if args:
        executable = safe_path(args[0], selected['expected_home'])
        if executable:
            paths.add(executable)
    program = safe_path(value.get('Program'), selected['expected_home'])
    if program:
        paths.add(program)
    projected = []
    for i, arg in enumerate(args):
        budget.gate()
        if not isinstance(arg, str) or not arg.startswith('--'):
            continue
        flag, equal, scalar = arg[2:].partition('=')
        lowered = flag.lower()
        if lowered not in ENDPOINT_FIELDS | HOST_FIELDS | PORT_FIELDS | PATH_FIELDS:
            continue
        scalar = scalar if equal else args[i + 1] if i + 1 < len(args) else None
        if lowered in PATH_FIELDS:
            ref = safe_path(scalar, selected['expected_home'])
            if ref:
                paths.add(ref)
            continue
        ep = endpoint(scalar) if lowered not in PORT_FIELDS else None
        if lowered in PORT_FIELDS and isinstance(scalar, str) and scalar.isdigit() and 0 < int(scalar) < 65536:
            ep = {'host': None, 'port': int(scalar), 'scheme': None}
        if ep:
            projected.append({'field': 'ProgramArguments/--' + flag, 'direction': direction(flag), 'endpoint': ep})
    env = value.get('EnvironmentVariables', {})
    env = env if isinstance(env, dict) else {}
    # v3 is names-only for every environment field, including proxy variables.
    return {'launch_label': safe_label(value.get('Label')), 'program': program,
            'argument_count': len(value.get('ProgramArguments', [])) if isinstance(value.get('ProgramArguments', []), list) else None,
            'path_references': sorted(paths), 'endpoints': projected,
            'environment_field_names': sorted(safe_field(k) for k in env)[:64],
            'environment_values_emitted': False, 'runtime_consumption_verified': False}


def classify(path):
    name = PurePosixPath(path).name.lower()
    if name.endswith(('.sqlite-wal', '.db-wal', '.sqlite-shm', '.db-shm')):
        return 'sqlite_wal_or_shm_metadata_only'
    if name.endswith(('.sqlite', '.sqlite3', '.db')):
        return 'database_header_only'
    if name in ('auth-profiles.json', 'auth-state.json') or name.endswith('.secret') or SENSITIVE_FILES.search(name):
        return 'credential_or_legacy_auth_metadata_only'
    if name.startswith('openclaw.json'):
        return 'openclaw_config_projection'
    if re.search(r'openbao|(?:^|[._-])bao(?:[._-]|$)|vault', name):
        if name.endswith(('.hcl', '.json', '.yaml', '.yml', '.service', '.timer', '.plist', '.sh', '.py')):
            return 'legacy_bao_entrypoint_projection'
        return 'legacy_bao_named_metadata_only'
    if name.endswith(('.tar', '.tgz', '.gz', '.zip', '.zst', '.snap', '.snapshot')):
        return 'archive_metadata_only_no_extraction'
    return 'metadata_only'


class Inspector:
    def __init__(self, selected, bounds):
        self.selected = selected
        self.budget = Budget(bounds)
        self.fs = NoFollowFilesystem(selected, self.budget)

    def projected_file(self, path, kind):
        result = self.fs.metadata(path)
        if not result.get('regular_file') or result.get('symlink'):
            return result
        try:
            maximum = self.budget.bounds['maximum_config_bytes'] if kind == 'openclaw_config_projection' else self.budget.bounds['maximum_code_bytes']
            if kind == 'database_header_only':
                raw = self.fs.read(path, 16, 'database_magic', prefix=True)
                result.update(self.fs.read_metadata[path])
                result.update(header_bytes_read=len(raw), sqlite_header_matches=raw == b'SQLite format 3\x00',
                              contents_read=False, database_rows_read=False)
                return result
            if kind not in ('openclaw_config_projection', 'legacy_bao_entrypoint_projection',
                            'endpoint_json', 'endpoint_yaml', 'pure_code_or_binary_metadata', 'plist'):
                return result
            if kind == 'pure_code_or_binary_metadata':
                prefix = self.fs.read(path, 16, 'executable_magic', prefix=True)
                result.update(self.fs.read_metadata[path])
                if prefix[:4] in (b'\x7fELF', b'\xcf\xfa\xed\xfe', b'\xfe\xed\xfa\xcf',
                                  b'\xce\xfa\xed\xfe', b'\xfe\xed\xfa\xce', b'\xca\xfe\xba\xbe'):
                    result.update(binary_header_class='ELF' if prefix[:4] == b'\x7fELF' else 'MachO_or_fat',
                                  header_bytes_read=len(prefix), contents_read=False)
                    return result
                if not prefix.startswith(b'#!'):
                    result['content_skip_reason'] = 'not_proven_pure_code'
                    return result
            raw = self.fs.read(path, maximum, 'approved_config' if kind == 'openclaw_config_projection' else 'approved_metadata_projection')
            result.update(self.fs.read_metadata[path])
            result.update(contents_read=True, source_sha256=sha(raw), credential_values_emitted=False)
            if kind == 'openclaw_config_projection':
                result['projection'] = openclaw_projection(bounded_json(raw, self.budget), self.selected, self.budget)
            elif kind == 'plist' or path.endswith('.plist'):
                result['projection'] = plist_projection(raw, self.selected, self.budget)
            elif kind == 'endpoint_json' or path.endswith('.json'):
                result['projection'] = endpoint_projection(bounded_json(raw, self.budget), self.budget, self.selected['expected_home'])
            else:
                result['projection'] = text_endpoint_projection(raw, self.budget, self.selected['expected_home'])
                if kind == 'pure_code_or_binary_metadata':
                    text = raw.decode('utf8')
                    literals = []
                    for match in re.finditer(r'\b(?:https?|socks5|tcp|tls)://[^\s\'"<>()]{1,4096}', text):
                        self.budget.gate()
                        ep = endpoint(match.group(0))
                        if ep and ep not in literals:
                            literals.append(ep)
                        if len(literals) == 64:
                            break
                    result['projection']['pure_code_endpoint_literals'] = literals
                    result['projection']['literal_direction_and_runtime_use_unverified'] = True
        except (OSError, ValueError, TypeError, UnicodeError, RecursionError, Refused, BudgetExceeded) as exc:
            result['projection_error'] = type(exc).__name__
            if isinstance(exc, (Refused, BudgetExceeded)):
                result['reason'] = exc.args[0]
        return result

    def backup_tree(self, item):
        root = item['path']
        result = {'path': root, 'kind': item['kind'], 'baseline': item['baseline'],
                  'current': self.projected_file(root, classify(root)), 'entries': [],
                  'backup_consistency_verified': False, 'restore_qualified': False}
        if not result['current'].get('directory') or result['current'].get('symlink'):
            return result
        queue = [(root, 0)]
        while queue:
            parent, depth = queue.pop(0)
            try:
                children, hit = self.fs.children(parent)
                if hit:
                    result.setdefault('bounded_directories', []).append(parent)
                for child in children:
                    path = child.get('path')
                    if not path:
                        result['entries'].append(child)
                        continue
                    child['depth'] = depth + 1
                    child['classification'] = classify(path)
                    if child.get('regular_file'):
                        child['inspection'] = self.projected_file(path, child['classification'])
                    elif child.get('directory') and not child.get('symlink'):
                        if PurePosixPath(path).name.lower() in SENSITIVE_DIRS:
                            child['recursion_skipped'] = 'sensitive_subtree_metadata_only'
                        elif depth + 1 < self.budget.bounds['maximum_depth']:
                            queue.append((path, depth + 1))
                        else:
                            child['recursion_skipped'] = 'maximum_depth'
                            self.budget.hits.add('maximum_depth')
                    result['entries'].append(child)
            except (OSError, Refused, BudgetExceeded) as exc:
                result.setdefault('scan_failures', []).append({'path': parent, 'error_class': type(exc).__name__})
                if isinstance(exc, BudgetExceeded):
                    break
        result['full_tree_enumerated'] = False
        return result

    def run(self, host, plan_digest):
        selected = self.selected
        config = self.projected_file(selected['config']['path'], 'openclaw_config_projection')
        config['baseline_sha256'] = selected['config']['sha256']
        config['matches_baseline'] = config.get('source_sha256') == selected['config']['sha256']
        projected = config.get('projection', {})
        secretrefs, missing, relay = [], [], []
        for expected in selected['secretrefs']:
            meta = self.fs.metadata(expected['path'], parents=True)
            meta.update(provider_id=expected['id'], source='file', payload_opened=False,
                        owner_matches_expected_uid=meta.get('uid') == selected['expected_uid'],
                        private_regular_file_metadata=bool(meta.get('regular_file') and not meta.get('symlink') and
                                                          not meta.get('group_or_other_access')),
                        credential_source_qualified=False, migration_complete=False)
            meta['current_configuration'] = next((x for x in projected.get('known_secret_providers', [])
                                                   if x['id'] == expected['id']), None)
            meta['consumer_locations'] = [x['config_pointer'] for x in projected.get('secretref_consumer_locations', [])
                                           if x['provider'] == expected['id']]
            secretrefs.append(meta)
        for expected in selected['missing_agents']:
            current = [x for x in projected.get('agents', []) if x['id'] == expected['agent_id']]
            resolution = 'current_config_reference_absent_or_ambiguous'
            if len(current) == 1:
                if current[0]['agent_dir_explicit']:
                    resolution = 'explicit_config_matches_original_path' if current[0]['declared_agent_dir'] == expected['agent_dir'] else 'explicit_config_differs_original_path'
                else:
                    resolution = 'no_explicit_agent_dir_original_receipt_default_scope_only'
            missing.append({'agent_id': expected['agent_id'], 'planned_agent_dir': expected['agent_dir'],
                            'config_references': current, 'configured_exactly_once': len(current) == 1,
                            'directory_reference_resolution': resolution,
                            'directory': self.fs.metadata(expected['agent_dir'], parents=True),
                            'store_files': [self.projected_file(path, classify(path)) for path in expected['existing_file_references']],
                            'owner_sdk_inspection_qualified': False, 'migration_complete': False})
        for expected in selected['relay_startups']:
            meta = self.projected_file(expected['path'], 'plist')
            meta.update(baseline_sha256=expected['sha256'], matches_baseline=meta.get('source_sha256') == expected['sha256'])
            actual = meta.get('projection', {}).get('path_references', [])
            meta['new_references_not_followed'] = [p for p in actual if p not in expected['existing_path_references']]
            relay.append(meta)
        dependencies = [self.projected_file(v['path'], v['inspection']) for v in selected['relay_dependencies']]
        backups = [self.backup_tree(v) for v in selected['backup_runtime']]
        final_config_metadata = self.fs.metadata(selected['config']['path'])
        config['same_file_metadata_at_scan_end'] = all(config.get(k) == final_config_metadata.get(k) for k in
                    ('dev', 'inode', 'size', 'mtime_ns', 'ctime_ns')) and final_config_metadata.get('exists') is True
        config['final_metadata'] = final_config_metadata
        gaps = [{'id': 'production_consistent_backup_restore', 'status': 'unqualified',
                 'next_action': 'Select actual owner-consistent snapshots for the observed databases, WAL state and bounded backup paths; qualify cold restore and rollback separately.'},
                {'id': 'client_cutover', 'status': 'unqualified',
                 'next_action': 'Complete real owner credential read/write, restart and rollback before changing each production client endpoint.'},
                {'id': 'legacy_cleanup', 'status': 'blocked',
                 'next_action': 'Resolve all enumerated client, relay, backup and separate-host boundaries before deleting any old Bao asset.'}]
        for item in missing:
            gaps.append({'id': 'configured_agent:' + item['agent_id'], 'path': item['planned_agent_dir'],
                         'status': 'owner_scope_not_qualified', 'next_action': 'Reconcile the actual current config reference and directory; run the real owner SDK inspector only after the exact owner path is established.'})
        for item in secretrefs:
            status = ('missing_owner_file' if item.get('exists') is False else
                      'owner_metadata_unresolved' if item.get('exists') is not True else
                      'owner_or_private_mode_mismatch' if not item['owner_matches_expected_uid'] or not item['private_regular_file_metadata'] else
                      'metadata_only_payload_and_consumer_unqualified')
            gaps.append({'id': 'secretref:' + item['provider_id'], 'path': item['path'],
                         'status': status, 'next_action': 'Use the approved credential owner/export and real consumer canary; this metadata receipt does not resolve or export the file payload.'})
        for item in backups:
            gaps.append({'id': 'backup_runtime:' + sha(item['path'].encode())[:16],
                         'path': item['path'], 'kind': item['kind'],
                         'status': 'missing_reference' if item['current'].get('exists') is False else 'bounded_metadata_only_restore_unqualified',
                         'next_action': 'Reconcile this exact path and its bounded observed children with the actual owner backup/restore or runtime consumer; preserve it until a real restore and rollback receipt exists.'})
        if relay:
            gaps.append({'id': 'mac_relay_dependency_qualification', 'status': 'configured_metadata_only',
                         'next_action': 'Use these four startup and endpoint references to qualify actual relay consumers and backend behavior. auth/nodes.json and internal key payloads were not read.'})
        return {'schema': SCHEMA, 'created_at': datetime.now(timezone.utc).isoformat(),
                'host_label': host, 'host_label_is_caller_asserted': True,
                'source_binding': {'receipt_set_sha256': PLAN['source_receipt_set_sha256'], 'allowlist_canonical_sha256': plan_digest,
                                   'original_metadata_receipt': selected['receipt']},
                'read_only': True, 'network_called': False, 'subprocess_called': False, 'sql_called': False,
                'sdk_imported': False, 'credential_file_payloads_read': False, 'credential_values_emitted': False,
                'production_mutation': False, 'configuration_references': config,
                'missing_agents': missing, 'secretref_metadata': secretrefs,
                'authbus_binding_metadata': [dict(self.fs.metadata(v['path'], parents=True), kind=v['kind']) for v in selected['binding_files']],
                'backup_runtime_entries': backups, 'relay_startups': relay, 'relay_dependencies': dependencies,
                'reused_evidence': {'freshly_scanned': False, 'observed_at': selected['receipt']['created_at'],
                                    'client_store_metadata': selected['reused_existing_store_metadata'],
                                    'entrypoint_metadata': selected['reused_entrypoint_metadata']},
                'pending_boundaries': PLAN['pending_boundaries'], 'gaps': gaps,
                'execution_bounds': {**self.budget.bounds, 'elapsed_seconds': round(time.monotonic() - self.budget.started, 6),
                                     'bytes_read': self.budget.bytes_read, 'directory_entries_seen': self.budget.entries,
                                     'directories_enumerated': self.budget.directories, 'bounds_hit': sorted(self.budget.hits),
                                     'content_read_operations': self.fs.content_reads,
                                     'filesystem_interruption_requires_caller_process_timeout': True},
                'qualification': {'allClientsAndBackupsMigrated': False, 'backupRestoreQualified': False,
                                  'providerLivenessQualified': False, 'productionCutoverQualified': False,
                                  'legacyCleanupQualified': False, 'metadataOnly': True}}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--host', choices=('main', 'macbook-pro', 'rog', 'pocket4'), required=True)
    parser.add_argument('--show-allowlist', action='store_true')
    args = parser.parse_args()
    selected = PLAN['hosts'][args.host]
    plan_digest = sha(json.dumps(PLAN, ensure_ascii=False, sort_keys=True, separators=(',', ':')).encode())
    if args.show_allowlist:
        print(json.dumps({'schema': PLAN['schema'], 'host': args.host, 'allowlist_canonical_sha256': plan_digest,
                          'source_receipt_set_sha256': PLAN['source_receipt_set_sha256'], 'bounds': PLAN['bounds'],
                          'host_allowlist': selected, 'pending_boundaries': PLAN['pending_boundaries']}, sort_keys=True))
        return 0
    if str(Path.home()) != selected['expected_home'] or os.geteuid() != selected['expected_uid'] or platform.system() != selected['expected_platform']:
        print(json.dumps({'schema': SCHEMA, 'host_label': args.host, 'ok': False,
                          'error_class': 'HostOwnerContextMismatch', 'paths_inspected': 0,
                          'read_only': True, 'production_mutation': False,
                          'qualification': {'allClientsAndBackupsMigrated': False, 'legacyCleanupQualified': False}}))
        return 2
    def alarm(_signum, _frame):
        raise BudgetExceeded('hard_alarm')
    old = signal.signal(signal.SIGALRM, alarm)
    signal.setitimer(signal.ITIMER_REAL, PLAN['bounds']['hard_alarm_seconds'])
    try:
        inspector = Inspector(selected, PLAN['bounds'])
        result = inspector.run(args.host, plan_digest)
        print(json.dumps(result, ensure_ascii=False, sort_keys=True, separators=(',', ':')))
        return 0
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, old)


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(json.dumps({'schema': SCHEMA, 'ok': False, 'error_class': type(exc).__name__,
                          'read_only': True, 'production_mutation': False,
                          'qualification': {'allClientsAndBackupsMigrated': False, 'legacyCleanupQualified': False}}))
        raise SystemExit(2)
