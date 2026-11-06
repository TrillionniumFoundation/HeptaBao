#!/usr/bin/env python3
"""Real isolated Chromium + native Rust host + local HTTPS login fixture.

Only synthetic credentials are generated. The local fixture's self-signed TLS
certificate is accepted by the test browser; this is not a TLS trust test.
The production extension manifest is loaded byte-for-byte. No host permission
is added to make a failing activeTab path pass.
"""
import argparse
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import importlib.util
import importlib.metadata
import json
import os
from pathlib import Path
import secrets
import ssl
import subprocess
import threading
import time
import urllib.parse

ROOT = Path(__file__).resolve().parents[2]
REQUIRED_CASES = (
    "vault_init", "vault_put", "expected_extension_loaded", "production_permissions_unchanged",
    "actual_action_popup", "exact_origin_item_selected", "real_form_filled", "no_automatic_submit",
    "fill_then_lock_acknowledged", "actual_login_accepted", "locked_stale_fill_denied",
    "fake_domain_empty_matches", "fake_domain_stale_fill_denied", "cross_origin_form_denied",
    "get_form_denied", "submit_override_denied", "external_submit_override_denied",
    "hidden_password_denied", "ambiguous_password_denied", "renderer_expired_authorization_denied",
    "fake_domain_renderer_denied", "child_frame_denied", "renderer_positive_controls_complete",
    "only_explicit_login_submitted", "vault_list", "identity_unchanged",
)


def sha(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def identity(bin_dir, browser):
    return {
        "source_commit": subprocess.check_output(["git", "-C", str(ROOT), "rev-parse", "HEAD"], text=True).strip(),
        "source_tree": subprocess.check_output(["git", "-C", str(ROOT), "rev-parse", "HEAD^{tree}"], text=True).strip(),
        "source_dirty": bool(subprocess.check_output(["git", "-C", str(ROOT), "status", "--porcelain"], text=True)),
        "extension_sha256": {p.name: sha(p) for p in sorted((ROOT / "clients/chromium").iterdir()) if p.is_file()},
        "profile_sha256": sha(__file__),
        "installer_sha256": sha(ROOT / "tools/install_personal_browser.py"),
        "binary_sha256": {name: sha(bin_dir / name) for name in ("heptabao-vault", "heptabao-browser")},
        "browser_sha256": sha(browser),
    }


def execute(args):
    # Playwright 1.57 deliberately skips Chromium "other" targets by default.
    # Real extension action popups can use that target type. This changes only
    # driver attachment, not extension permissions or the browser's caller ID.
    os.environ["PW_CHROMIUM_ATTACH_TO_OTHER"] = "1"
    from playwright.sync_api import sync_playwright
    root = args.work.resolve()
    root.mkdir(mode=0o700, exist_ok=False)
    vault = root / "vault"; vault.mkdir(mode=0o700)
    bin_dir = args.bin_dir.resolve()
    before = identity(bin_dir, args.browser)
    password = "synthetic-master-" + secrets.token_urlsafe(32)
    secret = "synthetic-login-" + secrets.token_urlsafe(32)
    user = "synthetic-user@example.test"
    checks = []
    def check(name, passed):
        if name not in REQUIRED_CASES or any(x["name"] == name for x in checks): raise RuntimeError("case_inventory_mismatch")
        checks.append({"name": name, "passed": bool(passed)})
        if not passed: raise RuntimeError(name)
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *unused): pass
        def do_GET(self):
            page = b'<!doctype html><title>Synthetic Login</title><form method="post" action="/login"><label>User<input name="username" type="text" autocomplete="username"></label><label>Password<input name="password" type="password" autocomplete="current-password"></label><button type="submit">Login</button></form>'
            self.send_response(200); self.send_header("Content-Type", "text/html"); self.send_header("Content-Length", str(len(page))); self.end_headers(); self.wfile.write(page)
        def do_POST(self):
            length = int(self.headers.get("Content-Length", "0"))
            if length > 8192: self.send_error(413); return
            values = urllib.parse.parse_qs(self.rfile.read(length).decode())
            valid = self.path == "/login" and values.get("username") == [user] and values.get("password") == [secret]
            self.server.login_count += int(valid)
            body = b"login_ok" if valid else b"login_rejected"
            self.send_response(200 if valid else 403); self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.login_count = 0
    cert, key = root / "fixture.crt", root / "fixture.key"
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-subj", "/CN=login.example.test", "-addext", "subjectAltName=DNS:login.example.test,DNS:evil.example.test", "-keyout", str(key), "-out", str(cert)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True, timeout=30)
    key.chmod(0o600)
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); tls.load_cert_chain(cert, key)
    server.socket = tls.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
    origin = f"https://login.example.test:{server.server_port}"
    evil = f"https://evil.example.test:{server.server_port}"
    def vault_call(command, body):
        result = subprocess.run([str(bin_dir / "heptabao-vault"), str(vault), command], input=json.dumps(body).encode(), stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
        check("vault_" + command, result.returncode == 0)
        return json.loads(result.stdout)
    report = {"schema": 2, "synthetic_only": True, "real_browser": True, "fixture_tls_trust_test": False, "production_qualified": False, "checks": checks,
              "identity_before": before, "playwright_version": importlib.metadata.version("playwright"), "headless": not args.headed,
              "driver_attach_to_other_targets": True, "action_invocations": [], "renderer_component_world": "CDP isolated world",
              "renderer_component_tests_are_extension_e2e": False, "started_unix_ns": time.time_ns()}
    try:
        vault_call("init", {"password": password, "output": str(root / "recovery.json")})
        vault_call("put", {"password": password, "expected_revision": 0, "item": {"id": "login-fixture", "kind": "login", "title": "Synthetic login", "username": user, "origin": origin, "secret": secret, "notes": "", "totp": None}})
        xdg = root / "xdg"; xdg.mkdir(mode=0o700)
        env = dict(os.environ, XDG_CONFIG_HOME=str(xdg), CHROME_CONFIG_HOME=str(xdg))
        with sync_playwright() as p:
            launch_args = ["--no-sandbox", "--no-proxy-server", f"--disable-extensions-except={ROOT / 'clients/chromium'}", f"--load-extension={ROOT / 'clients/chromium'}", "--host-resolver-rules=MAP *.example.test 127.0.0.1", "--disable-dev-shm-usage"]
            report["launch_args"] = launch_args
            context = p.chromium.launch_persistent_context(str(root / "profile"), executable_path=str(args.browser), headless=not args.headed, env=env, ignore_https_errors=True, args=launch_args)
            try:
                def expected_worker(candidate):
                    return candidate.url.startswith("chrome-extension://") and candidate.url.endswith("/worker.js")
                worker = next((w for w in context.service_workers if expected_worker(w)), None)
                if worker is None: worker = context.wait_for_event("serviceworker", predicate=expected_worker, timeout=15000)
                # Observe only browser-supplied sender identity. Do not intercept
                # port messages, native frames, passwords or credential fields.
                worker.evaluate("""() => {
                  globalThis.__qaPopupConnections=[];
                  chrome.runtime.onConnect.addListener(port=>{
                    if(port.name==='vault-popup') globalThis.__qaPopupConnections.push({
                      name:port.name, senderId:port.sender?.id, senderUrl:port.sender?.url,
                      documentId:port.sender?.documentId??null,
                      origin:port.sender?.origin??null, hasTab:!!port.sender?.tab
                    });
                  });
                }""")
                extension_id = urllib.parse.urlsplit(worker.url).hostname
                check("expected_extension_loaded", worker.evaluate("chrome.runtime.getManifest().name") == "HeptaBao Personal Vault Preview")
                runtime_manifest = worker.evaluate("chrome.runtime.getManifest()")
                check("production_permissions_unchanged", runtime_manifest == json.loads((ROOT / "clients/chromium/manifest.json").read_text())
                      and runtime_manifest.get("permissions") == ["activeTab", "scripting", "nativeMessaging"]
                      and not runtime_manifest.get("host_permissions"))
                report["extension_id"] = extension_id
                report["browser_version"] = context.browser.version if context.browser else subprocess.check_output([str(args.browser), "--version"], text=True).strip()
                installer_spec = importlib.util.spec_from_file_location("installer", ROOT / "tools/install_personal_browser.py")
                installer = importlib.util.module_from_spec(installer_spec); installer_spec.loader.exec_module(installer)
                # Chromium's user-level native manifests are under the actual
                # --user-data-dir, which this test owns, not a guessed default.
                manifests = root / "profile/NativeMessagingHosts"
                installed = installer.install(bin_dir / "heptabao-browser", vault, root / "host", manifests, extension_id, 60)
                manifest_paths = [Path(installed["manifest"])]
                report["native_installation_sha256"] = {str(path.relative_to(root)): sha(path) for path in [*manifest_paths, root / "host/native-host", root / "host/config.json"]}
                page = context.pages[0]; page.goto(origin, wait_until="load"); page.bring_to_front()
                def action_popup():
                    page.bring_to_front()
                    # Chrome's CDP extension action dispatch follows the real
                    # browser action path and grants activeTab for this tab.
                    # action.openPopup() only opens UI and does not grant it.
                    # No host permission or physical keypress is claimed here.
                    cdp = context.browser.new_browser_cdp_session()
                    targets = cdp.send("Target.getTargets", {"filter": [{}]})["targetInfos"]
                    tabs = [t for t in targets if t["type"] == "tab" and t["url"] == page.url]
                    if len(tabs) != 1: raise RuntimeError("action_tab_identity_ambiguous")
                    cdp.send("Extensions.triggerAction", {"id": extension_id, "targetId": tabs[0]["targetId"]})
                    cdp.detach()
                    report["action_invocations"].append("CDP Extensions.triggerAction on exact tab target")
                    deadline = time.monotonic() + 10
                    while time.monotonic() < deadline:
                        for candidate in context.pages:
                            if candidate.url == f"chrome-extension://{extension_id}/popup.html": return candidate
                        page.wait_for_timeout(100)
                    if context.browser:
                        cdp = context.browser.new_browser_cdp_session()
                        report["popup_diagnostic_targets"] = [{"type": t["type"], "url": t["url"]} for t in cdp.send("Target.getTargets")["targetInfos"]]
                        cdp.detach()
                    return None
                popup = action_popup()
                check("actual_action_popup", popup is not None)
                popup.locator("#master").fill(password)
                popup.locator("#unlock-form button").click()
                popup.locator("#items option").wait_for(state="attached", timeout=15000)
                popup.locator("#matches").wait_for(state="visible", timeout=5000)
                check("exact_origin_item_selected", popup.locator("#items option").count() == 1 and popup.locator("#fill").is_enabled())
                popup.locator("#fill").click()
                page.wait_for_function("document.querySelector('input[type=password]').value.length > 0", timeout=10000)
                check("real_form_filled", page.locator("input[name=username]").input_value() == user and page.locator("input[name=password]").input_value() == secret)
                check("no_automatic_submit", server.login_count == 0)
                # The browser adapter's final result confirms it also locked.
                popup.locator("#status").filter(has_text="已填充并锁定").wait_for(timeout=10000)
                check("fill_then_lock_acknowledged", True)
                popup.close()
                page.locator("button[type=submit]").click(); page.wait_for_load_state("load")
                check("actual_login_accepted", page.locator("body").inner_text() == "login_ok" and server.login_count == 1)

                # A stale client selection travels through the unchanged real
                # popup -> worker -> native host path. Only the test UI state is
                # made stale; no production file or permission is modified.
                def stale_fill_denied(popup, name):
                    popup.evaluate("""() => {
                      document.querySelector('#items').replaceChildren(new Option('stale selection','login-fixture'));
                      document.querySelector('#matches').hidden=false;
                      document.querySelector('#fill').disabled=false;
                      document.querySelector('#status').textContent='test_pending';
                      document.querySelector('#fill').click();
                    }""")
                    popup.locator("#status").filter(has_text="请求被拒绝").wait_for(timeout=15000)
                    check(name, page.locator("input[name=username]").input_value() == "" and page.locator("input[name=password]").input_value() == "")
                page.goto(origin, wait_until="load"); popup = action_popup()
                if popup is None: raise RuntimeError("locked_action_popup_missing")
                stale_fill_denied(popup, "locked_stale_fill_denied")
                popup.close()
                page.goto(evil, wait_until="load"); popup = action_popup()
                if popup is None: raise RuntimeError("fake_domain_action_popup_missing")
                popup.locator("#master").fill(password); popup.locator("#unlock-form button").click()
                popup.locator("#status").filter(has_text="没有精确匹配条目").wait_for(timeout=15000)
                check("fake_domain_empty_matches", popup.locator("#items option").count() == 0 and not popup.locator("#fill").is_enabled())
                stale_fill_denied(popup, "fake_domain_stale_fill_denied")
                popup.close()

                # These are renderer component tests in a real CDP isolated
                # world, distinct from the full extension/native tests above.
                # Each rejection gets a fresh successful positive control and
                # must throw its exact expected reason with every input intact.
                module_source = (ROOT / "clients/chromium/fill.js").read_text().replace("export function", "function")
                component = context.new_cdp_session(page)
                def isolated(frame_id=None):
                    frame_id = frame_id or component.send("Page.getFrameTree")["frameTree"]["frame"]["id"]
                    world_id = component.send("Page.createIsolatedWorld", {"frameId": frame_id, "worldName": "heptabao-qa-component"})["executionContextId"]
                    def evaluate(expression):
                        result = component.send("Runtime.evaluate", {"expression": expression, "contextId": world_id, "returnByValue": True})
                        if "exceptionDetails" in result: raise RuntimeError("component_evaluation_failed")
                        return result["result"].get("value")
                    evaluate(module_source + "; globalThis.__inspect=inspectLogin; globalThis.__fill=fillLogin; true")
                    return evaluate
                def positive_control():
                    page.goto(origin, wait_until="load"); page.bring_to_front()
                    evaluate = isolated()
                    expected = evaluate("__inspect(location.href)")
                    ok = evaluate("(() => {let e=__inspect(location.href);e.notAfter=performance.timeOrigin+performance.now()+1000;let r=__fill(e,'component-user','component-pass');return r.filled && [...document.querySelectorAll('input')].map(x=>x.value).join('|')==='component-user|component-pass';})()")
                    if not ok: raise RuntimeError("component_positive_control_failed")
                    page.evaluate("document.querySelectorAll('input').forEach(x=>x.value='')")
                    report["renderer_positive_controls"] = report.get("renderer_positive_controls", 0) + 1
                    return evaluate, expected
                def denied(evaluate, expected, error, expired=False):
                    return evaluate("(() => {const e=" + json.dumps(expected) + ";e.notAfter=performance.timeOrigin+performance.now()+" + ("-1" if expired else "1000") + ";const before=[...document.querySelectorAll('input')].map(x=>x.value);try {__fill(e,'component-user','component-pass');return false;}catch(error){return error.message===" + json.dumps(error) + " && JSON.stringify(before)===JSON.stringify([...document.querySelectorAll('input')].map(x=>x.value));}})()")
                def reject(name, mutate, error):
                    evaluate, expected = positive_control()
                    page.evaluate(mutate)
                    check(name, denied(evaluate, expected, error))
                reject("cross_origin_form_denied", f"document.querySelector('form').action={json.dumps(evil + '/login')}", "form_changed")
                reject("get_form_denied", "document.querySelector('form').method='GET'", "form_changed")
                reject("submit_override_denied", f"document.querySelector('button').setAttribute('formaction',{json.dumps(evil + '/login')})", "submit_target_rejected")
                reject("external_submit_override_denied", f"document.querySelector('form').id='login'; const b=document.createElement('button');b.setAttribute('form','login');b.setAttribute('formaction',{json.dumps(evil + '/login')});document.body.append(b)", "submit_target_rejected")
                reject("hidden_password_denied", "document.querySelector('input[type=password]').style.display='none'", "ambiguous_password_form")
                reject("ambiguous_password_denied", "document.querySelector('form').appendChild(document.querySelector('input[type=password]').cloneNode())", "ambiguous_password_form")
                evaluate, expected = positive_control()
                check("renderer_expired_authorization_denied", denied(evaluate, expected, "fill_authorization_expired", expired=True))
                evaluate, expected = positive_control()
                page.goto(evil, wait_until="load"); evaluate = isolated()
                check("fake_domain_renderer_denied", denied(evaluate, expected, "page_changed_or_inactive"))
                evaluate, expected = positive_control()
                page.goto(origin, wait_until="load")
                page.evaluate("document.body.innerHTML='<iframe srcdoc=\"<form method=post><input type=text><input type=password></form>\"></iframe>'")
                page.frame_locator("iframe").locator("input[type=password]").wait_for(state="attached", timeout=5000)
                children = component.send("Page.getFrameTree")["frameTree"].get("childFrames", [])
                if len(children) != 1: raise RuntimeError("child_frame_missing")
                evaluate = isolated(children[0]["frame"]["id"])
                check("child_frame_denied", denied(evaluate, expected, "page_changed_or_inactive"))
                check("renderer_positive_controls_complete", report.get("renderer_positive_controls") == 9)
                check("only_explicit_login_submitted", server.login_count == 1)
                component.detach()
            finally:
                if not any(x["name"] == "only_explicit_login_submitted" and x["passed"] for x in checks):
                    # Fixed UI states and browser identities only. Do not read
                    # any master input, credential field value or native frame.
                    try:
                        report["failure_browser_state"] = worker.evaluate("""async()=>{
                          const tabs=await chrome.tabs.query({active:true,lastFocusedWindow:true});
                          return Promise.all(tabs.map(async t=>({tabId:t.id,url:t.url,active:t.active,window:await chrome.windows.get(t.windowId)})));
                        }""")
                        report["failure_popup_status"] = [q.locator("#status").text_content(timeout=500) for q in context.pages if q.url.endswith("/popup.html")]
                        report["failure_document_state"] = page.evaluate("({visibility:document.visibilityState,focused:document.hasFocus(),url:location.href})")
                        report["failure_popup_connections"] = worker.evaluate("globalThis.__qaPopupConnections")
                        report["failure_runtime_contexts"] = worker.evaluate("chrome.runtime.getContexts({contextTypes:['POPUP']})")
                    except Exception:
                        report["failure_diagnostics_unavailable"] = True
                context.close()
        # A successful reopen requires all extension-owned vault sessions to be
        # gone; no test kills unrelated browser or native-host processes.
        vault_call("list", {"password": password})
        check("identity_unchanged", identity(bin_dir, args.browser) == before)
        if len(checks) != len(REQUIRED_CASES): raise RuntimeError("case_inventory_incomplete")
        report["status"] = "passed"
    except Exception as error:
        report["status"] = "failed"
        report["error_type"] = type(error).__name__
        # Only fixed test case names can leave the private test directory.
        report["failed_case"] = next((x["name"] for x in checks if not x["passed"]), "browser_operation_failed")
        (root / "failure.private.txt").write_text(str(error))
        (root / "failure.private.txt").chmod(0o600)
    finally:
        server.shutdown(); server.server_close(); thread.join(timeout=3)
    report["passed"] = sum(x["passed"] for x in checks)
    report["observed"] = len(checks)
    report["expected_count"] = len(REQUIRED_CASES)
    report["required_cases"] = REQUIRED_CASES
    report["missing_cases"] = sorted(set(REQUIRED_CASES) - {x["name"] for x in checks})
    report["identity_after"] = identity(bin_dir, args.browser)
    report["finished_unix_ns"] = time.time_ns()
    args.report.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report))
    return report["status"] == "passed"


if __name__ == "__main__":
    parser=argparse.ArgumentParser(); parser.add_argument("--browser", type=Path, required=True); parser.add_argument("--bin-dir", type=Path, default=ROOT/"target/debug"); parser.add_argument("--work", type=Path, required=True); parser.add_argument("--report", type=Path, required=True); parser.add_argument("--headed", action="store_true")
    args=parser.parse_args()
    if args.report.exists(): raise SystemExit("report_already_exists")
    raise SystemExit(0 if execute(args) else 1)
