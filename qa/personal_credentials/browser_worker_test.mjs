#!/usr/bin/env node
/**
 * Scheduling unit tests for the actual Chromium service-worker module.
 *
 * Chrome APIs and native messaging are controlled doubles. No DOM is rendered,
 * no browser is launched, and no native-host binary is executed here. These
 * cases do not constitute browser/native-messaging or platform qualification.
 * Run: node --test qa/personal_credentials/browser_worker_test.mjs
 */
import assert from "node:assert/strict";
import {readFileSync} from "node:fs";
import {setImmediate as turn} from "node:timers/promises";
import nodeTest from "node:test";
const test = (name, callback) => nodeTest(name, {timeout: 3000, concurrency: false}, callback);

const workerPath = new URL("../../clients/chromium/worker.js", import.meta.url);
const fillPath = new URL("../../clients/chromium/fill.js", import.meta.url);
const workerSource = readFileSync(workerPath, "utf8");
const fillModule = `data:text/javascript;base64,${Buffer.from(readFileSync(fillPath, "utf8")).toString("base64")}`;
const importLine = 'import {inspectLogin, fillLogin} from "./fill.js";';
assert.equal(workerSource.split(importLine).length, 2, "load the real worker with exactly its fill-module import replaced");
const workerModule = `data:text/javascript;base64,${Buffer.from(workerSource.replace(importLine,
  `import {inspectLogin, fillLogin} from ${JSON.stringify(fillModule)};`)).toString("base64")}`;
const EXTENSION_ID = "a".repeat(32);
const POPUP_URL = `chrome-extension://${EXTENSION_ID}/popup.html`;
const POPUP_DOCUMENT_ID = "popup-document-1";
const ORIGIN = "https://login.example.test";
const PAGE_URL = `${ORIGIN}/login`;
const SYNTHETIC_PASSWORD = "synthetic-worker-password";
const SYNTHETIC_USERNAME = "synthetic-worker-account";
const SYNTHETIC_MASTER = "synthetic-worker-master";
let moduleNumber = 0;

function deferred() {
  let resolve;
  const promise = new Promise((done) => { resolve = done; });
  return {promise, resolve};
}

function event() {
  const listeners = [];
  return {
    addListener(listener) { listeners.push(listener); },
    fire(...args) { for (const listener of listeners) listener(...args); },
  };
}

async function until(predicate, explanation) {
  // A blocked API is always explicitly released by the test. This bounded
  // event-loop drain is for Promise continuations, never a timing sleep.
  for (let attempts = 0; attempts < 100; attempts++) {
    if (predicate()) return;
    await turn();
  }
  assert.fail(explanation);
}

async function harness(options = {}) {
  const priorChrome = globalThis.chrome;
  const priorSetTimeout = globalThis.setTimeout;
  const priorClearTimeout = globalThis.clearTimeout;
  const priorPerformance = Object.getOwnPropertyDescriptor(globalThis, "performance");
  const timeOrigin = globalThis.performance.timeOrigin;
  let taskNow = 1000;
  Object.defineProperty(globalThis, "performance", {configurable: true, value: {timeOrigin, now: () => taskNow}});
  const timers = new Set();
  const timerDetails = new Map();
  globalThis.setTimeout = (callback, delay, ...args) => {
    const timer = priorSetTimeout(() => { timers.delete(timer); timerDetails.delete(timer); callback(...args); }, delay);
    timer.unref();
    timers.add(timer);
    timerDetails.set(timer, {callback, delay, args});
    return timer;
  };
  globalThis.clearTimeout = (timer) => { timers.delete(timer); timerDetails.delete(timer); priorClearTimeout(timer); };
  const gates = new Map();
  const nativeRequests = [];
  const nativeReplies = [];
  const popupMessages = [];
  const scriptCalls = [];
  const credentials = [];
  const trace = [];
  let nativeConnections = 0;
  let contextQueries = 0;
  let postAfterNativeDisconnect = 0;
  let restored = false;

  function hold(stage) {
    assert.ok(!gates.has(stage), "one explicit scheduling gate per stage");
    const arrived = deferred(), release = deferred();
    const gate = {arrived: arrived.promise, release: release.resolve, releasePromise: release.promise};
    gates.set(stage, {...gate, arrive: arrived.resolve});
    return gate;
  }
  async function pause(stage) {
    const gate = gates.get(stage);
    if (gate) { gate.arrive(); await gate.releasePromise; }
  }

  const native = {
    onMessage: event(), onDisconnect: event(), closed: false,
    postMessage(message) {
      if (this.closed) { postAfterNativeDisconnect++; throw new Error("mock_native_disconnected"); }
      nativeRequests.push(structuredClone(message));
      trace.push(`native.request.${message.request.op}`);
      void (async () => {
        await pause(`native.${message.request.op}`);
        if (native.closed) return;
        const ok = options.rejectNativeOp !== message.request.op;
        let result;
        if (message.request.op === "fill" && ok) {
          result = {origin: options.credentialOrigin ?? ORIGIN,
            username: SYNTHETIC_USERNAME, password: SYNTHETIC_PASSWORD,
            valid_for_ms: Object.hasOwn(options, "validForMs") ? options.validForMs : 2000};
          credentials.push(result);
        } else if (message.request.op === "list") {
          result = [{id: "synthetic-item", title: "Synthetic item", origin: ORIGIN}];
        } else result = {locked: message.request.op !== "unlock"};
        const reply = ok ? {id: message.id, ok, result}
          : {id: message.id, ok, error: "synthetic-private-native-error"};
        nativeReplies.push({op: message.request.op, ok});
        trace.push(`native.reply.${message.request.op}`);
        native.onMessage.fire(reply);
      })();
    },
    disconnect() {
      if (this.closed) return;
      this.closed = true;
      trace.push("native.disconnected");
      this.onDisconnect.fire();
    },
  };
  const popup = {
    name: options.name ?? "vault-popup",
    sender: Object.hasOwn(options, "sender") ? options.sender : {id: EXTENSION_ID, url: POPUP_URL, documentId: POPUP_DOCUMENT_ID},
    onMessage: event(), onDisconnect: event(), closed: false,
    postMessage(message) {
      if (this.closed) throw new Error("mock_popup_disconnected");
      popupMessages.push(structuredClone(message));
      trace.push(`popup.${message.op ?? "error"}`);
      if (message.op === "check_focus" && options.autoFocusResponse !== false) {
        void (async () => {
          await pause("popup.focus");
          if (!this.closed) this.onMessage.fire({op: "focus_response", request_id: message.request_id,
            window_id: options.popupWindowId ?? 5, focused: options.popupFocused ?? true});
        })();
      }
    },
    disconnect() {
      if (this.closed) return;
      this.closed = true;
      trace.push("popup.disconnected");
      this.onDisconnect.fire();
    },
  };
  const onConnect = event();
  globalThis.chrome = {
    runtime: {id: EXTENSION_ID, getURL: (path) => `chrome-extension://${EXTENSION_ID}/${path}`,
      onConnect, connectNative() { nativeConnections++; return native; },
      async getContexts(filter) {
        const query = ++contextQueries;
        if (query === 1) {
          const expected = {contextTypes: ["POPUP"], documentUrls: [POPUP_URL]};
          if (popup.sender.documentId !== undefined) expected.documentIds = [popup.sender.documentId];
          assert.deepEqual(filter, expected, "initial binding uses a browser-owned popup registry lookup");
        } else {
          assert.deepEqual(filter, {contextTypes: ["POPUP"], documentIds: [POPUP_DOCUMENT_ID]},
            "later checks use the document bound at connection creation");
        }
        await pause("runtime.getContexts"); await pause(`runtime.getContexts.${query}`);
        return Object.hasOwn(options, "contexts") ? options.contexts : [{contextType: "POPUP",
          contextId: "popup-context-1", documentId: POPUP_DOCUMENT_ID, documentUrl: POPUP_URL, tabId: -1, windowId: -1}];
      }},
    tabs: {
      async query() { await pause("tabs.query"); return [{id: 7, url: options.tabUrl ?? PAGE_URL}]; },
      async get() { await pause("tabs.get"); return {active: options.active ?? true,
        windowId: 5, url: options.currentUrl ?? PAGE_URL}; },
    },
    windows: {async get() { await pause("windows.get"); return {focused: options.focused ?? true}; }},
    scripting: {async executeScript(details) {
      const inspect = details.func.name === "inspectLogin";
      scriptCalls.push({kind: inspect ? "inspect" : "fill", target: structuredClone(details.target),
        world: details.world, args: structuredClone(details.args)});
      trace.push(inspect ? "inspection.dispatched" : "fill.dispatched");
      await pause(inspect ? "scripting.inspect" : "scripting.fill");
      if (inspect) return [{frameId: options.frameId ?? 0,
        documentId: Object.hasOwn(options, "documentId") ? options.documentId : "document-1",
        result: {url: PAGE_URL, origin: ORIGIN, formAction: `${ORIGIN}/session`,
          usernameName: "username", passwordName: "password"}}];
      trace.push("fill.completed");
      return [{documentId: "document-1", result: {filled: options.rendererFilled ?? true, submitted: false}}];
    }},
  };
  await import(`${workerModule}#case-${++moduleNumber}`);
  onConnect.fire(popup);

  return {
    popup, native, nativeRequests, nativeReplies, popupMessages, scriptCalls, credentials, trace,
    hold, advance(milliseconds) { taskNow += milliseconds; },
    fireTimer(delay) {
      const item = [...timerDetails].find(([, detail]) => detail.delay === delay);
      assert.ok(item, `expected pending ${delay}ms timer`);
      const [timer, detail] = item;
      timers.delete(timer); timerDetails.delete(timer); priorClearTimeout(timer);
      detail.callback(...detail.args);
    },
    get monotonicEpochNow() { return timeOrigin + taskNow; },
    get nativeConnections() { return nativeConnections; },
    get contextQueries() { return contextQueries; },
    get postAfterNativeDisconnect() { return postAfterNativeDisconnect; },
    send(message) { popup.onMessage.fire(message); },
    fill() { popup.onMessage.fire({op: "fill", item_id: "synthetic-item"}); },
    unlock() { popup.onMessage.fire({op: "unlock", password: SYNTHETIC_MASTER}); },
    lock() { popup.onMessage.fire({op: "lock"}); },
    focusReply(overrides = {}) {
      const request = popupMessages.findLast((message) => message.op === "check_focus");
      assert.ok(request, "a reply must correspond to a real focus challenge");
      popup.onMessage.fire({op: "focus_response", request_id: request.request_id,
        window_id: 5, focused: true, ...overrides});
    },
    fills() { return scriptCalls.filter((call) => call.kind === "fill"); },
    calls(op) { return nativeRequests.filter((call) => call.request.op === op); },
    async cleanup() {
      if (restored) return;
      restored = true;
      popup.disconnect(); native.disconnect();
      for (const gate of gates.values()) gate.release();
      for (let i = 0; i < 5; i++) await turn();
      for (const timer of timers) priorClearTimeout(timer);
      globalThis.chrome = priorChrome;
      globalThis.setTimeout = priorSetTimeout;
      globalThis.clearTimeout = priorClearTimeout;
      Object.defineProperty(globalThis, "performance", priorPerformance);
    },
  };
}

function publicRepliesContainNoSecrets(h) {
  const publicBytes = JSON.stringify(h.popupMessages);
  for (const secret of [SYNTHETIC_PASSWORD, SYNTHETIC_USERNAME, SYNTHETIC_MASTER, "synthetic-private-native-error"])
    assert.ok(!publicBytes.includes(secret), "popup responses contain no credential or native error");
}

const rejectedSenders = [
  ["missing sender", undefined],
  ["external extension", {id: "b".repeat(32), url: POPUP_URL}],
  ["web page", {id: EXTENSION_ID, url: `${ORIGIN}/login`}],
  ["other extension page", {id: EXTENSION_ID, url: `chrome-extension://${EXTENSION_ID}/other.html`}],
  ["content script", {id: EXTENSION_ID, url: POPUP_URL, tab: {id: 7}}],
  ["empty popup document ID", {id: EXTENSION_ID, url: POPUP_URL, documentId: ""}],
  ["null popup document ID", {id: EXTENSION_ID, url: POPUP_URL, documentId: null}],
  ["non-string popup document ID", {id: EXTENSION_ID, url: POPUP_URL, documentId: 7}],
];
for (const [description, sender] of rejectedSenders) {
  test(`source gate rejects ${description} before native connection`, async (t) => {
    const h = await harness({sender}); t.after(() => h.cleanup());
    assert.equal(h.nativeConnections, 0);
    assert.equal(h.popup.closed, true);
    assert.equal(h.nativeRequests.length, 0);
  });
}
test("source gate rejects an incorrect port name", async (t) => {
  const h = await harness({name: "not-vault-popup"}); t.after(() => h.cleanup());
  assert.equal(h.nativeConnections, 0);
  assert.equal(h.popup.closed, true);
});

test("positive control dispatches one isolated document fill and then locks", async (t) => {
  const h = await harness(); t.after(() => h.cleanup());
  h.fill();
  await until(() => h.popupMessages.some((m) => m.op === "filled"), "successful fill must settle");
  assert.equal(h.fills().length, 1);
  assert.deepEqual(h.fills()[0].target, {tabId: 7, documentIds: ["document-1"]});
  assert.equal(h.fills()[0].world, "ISOLATED");
  const notAfter = h.fills()[0].args[0].notAfter;
  assert.ok(Number.isFinite(notAfter) && notAfter > h.monotonicEpochNow && notAfter <= h.monotonicEpochNow + 2000,
    "a finite renderer deadline must accompany the fill dispatch");
  assert.ok(h.calls("lock").length >= 1);
  assert.ok(h.credentials.every((c) => c.password === "" && c.username === ""));
  publicRepliesContainNoSecrets(h);
});

for (const stage of ["native.fill", "tabs.get", "windows.get"]) {
  test(`explicit lock cancels fill suspended at ${stage}`, async (t) => {
    const h = await harness(); t.after(() => h.cleanup());
    const gate = h.hold(stage);
    h.fill(); await gate.arrived;
    h.lock();
    gate.release();
    await until(() => h.popupMessages.some((m) => m.op === "locked" && m.ok), "explicit lock must be acknowledged");
    assert.equal(h.fills().length, 0, "no fill dispatch after revoking the in-flight ticket");
    assert.ok(h.calls("lock").length >= 1, "busy must not silently discard lock");
    assert.ok(!h.popupMessages.some((m) => m.op === "filled"));
    assert.ok(h.credentials.every((c) => c.password === "" && c.username === ""));
    publicRepliesContainNoSecrets(h);
  });
}

for (const stage of ["tabs.get", "windows.get"]) {
  test(`closing popup cancels already decrypted fill suspended at ${stage}`, async (t) => {
    const h = await harness(); t.after(() => h.cleanup());
    const gate = h.hold(stage);
    h.fill(); await gate.arrived;
    assert.equal(h.credentials.length, 1, "the race begins after receiving a credential");
    h.popup.disconnect();
    gate.release();
    await until(() => h.credentials.every((c) => c.password === "" && c.username === ""), "cancelled credential must be released");
    assert.equal(h.fills().length, 0);
    assert.equal(h.native.closed, true);
    assert.ok(!h.popupMessages.some((m) => m.op === "filled"));
    publicRepliesContainNoSecrets(h);
  });
}

test("lock during unlock suppresses subsequent listing and is not dropped", async (t) => {
  const h = await harness(); t.after(() => h.cleanup());
  const gate = h.hold("native.unlock");
  h.unlock(); await gate.arrived;
  h.lock(); gate.release();
  await until(() => h.popupMessages.some((m) => m.op === "locked" && m.ok), "lock after unlock must settle");
  assert.equal(h.calls("list").length, 0);
  assert.equal(h.fills().length, 0);
  assert.ok(h.calls("lock").length >= 1);
  publicRepliesContainNoSecrets(h);
});

test("new unlock remains blocked until pending lock acknowledgement", async (t) => {
  const h = await harness(); t.after(() => h.cleanup());
  const gate = h.hold("native.lock");
  h.lock(); await gate.arrived;
  h.unlock();
  for (let i = 0; i < 3; i++) await turn();
  assert.equal(h.calls("unlock").length, 0);
  gate.release();
  await until(() => h.popupMessages.some((m) => m.op === "locked" && m.ok), "pending lock must finish");
  h.unlock();
  await until(() => h.popupMessages.some((m) => m.op === "list"), "unlock may resume after confirmed lock");
  assert.equal(h.calls("unlock").length, 1);
  publicRepliesContainNoSecrets(h);
});

test("lock acknowledgement waits for an already dispatched fill outcome", async (t) => {
  const h = await harness(); t.after(() => h.cleanup());
  const gate = h.hold("scripting.fill");
  h.fill(); await gate.arrived;
  assert.equal(h.fills().length, 1, "dispatch cannot be pretended reversible");
  h.lock();
  for (let i = 0; i < 3; i++) await turn();
  assert.ok(!h.popupMessages.some((m) => m.op === "locked"), "must not acknowledge lock ahead of accepted dispatch");
  gate.release();
  await until(() => h.popupMessages.some((m) => m.op === "locked" && m.ok), "lock after accepted dispatch must settle");
  assert.ok(h.trace.indexOf("fill.completed") < h.trace.indexOf("popup.locked"));
  assert.ok(!h.popupMessages.some((m) => m.op === "filled"), "cancelled generation must not report later success");
  publicRepliesContainNoSecrets(h);
});

for (const [description, options] of [
  ["HTTP page", {tabUrl: "http://login.example.test/login"}],
  ["non-top inspection result", {frameId: 1}],
  ["missing browser document ID", {documentId: undefined}],
  ["navigation after inspection", {currentUrl: `${ORIGIN}/another-page`}],
  ["inactive tab", {active: false}],
  ["unfocused window and popup", {focused: false, popupFocused: false}],
  ["mismatched credential origin", {credentialOrigin: "https://different.example.test"}],
  ["expired native authorization", {rejectNativeOp: "fill"}],
]) {
  test(`fill denies ${description}`, async (t) => {
    const h = await harness(options); t.after(() => h.cleanup());
    h.fill();
    await until(() => h.popupMessages.some((m) => m.ok === false), "denial must settle without a credential-bearing error");
    assert.equal(h.fills().length, 0);
    assert.ok(h.credentials.every((c) => c.password === "" && c.username === ""));
    publicRepliesContainNoSecrets(h);
  });
}

for (const [description, validForMs] of [
  ["missing", undefined], ["expired", 0], ["unbounded", 2001], ["nonintegral", 1.5],
]) {
  test(`fill denies ${description} native authorization budget`, async (t) => {
    const h = await harness({validForMs}); t.after(() => h.cleanup());
    h.fill();
    await until(() => h.popupMessages.some((m) => m.ok === false), "invalid budget must deny before dispatch");
    assert.equal(h.fills().length, 0);
    assert.ok(h.credentials.every((c) => c.password === "" && c.username === ""));
    publicRepliesContainNoSecrets(h);
  });
}

for (const stage of ["native.fill", "tabs.get", "windows.get"]) {
  test(`fill expiry includes time suspended at ${stage}`, async (t) => {
    const h = await harness(); t.after(() => h.cleanup());
    const gate = h.hold(stage);
    h.fill(); await gate.arrived;
    h.advance(2001);
    gate.release();
    await until(() => h.popupMessages.some((m) => m.ok === false), "expired authority must not survive an asynchronous wait");
    assert.equal(h.fills().length, 0);
    assert.ok(h.credentials.every((c) => c.password === "" && c.username === ""));
    publicRepliesContainNoSecrets(h);
  });
}

const realPopupContext = {contextType: "POPUP", documentId: POPUP_DOCUMENT_ID,
  contextId: "popup-context-1", documentUrl: POPUP_URL, tabId: -1, windowId: -1};
for (const [description, contexts] of [
  ["missing context", []],
  ["ambiguous contexts", [realPopupContext, realPopupContext]],
  ["tab posing as popup", [{...realPopupContext, contextType: "TAB"}]],
  ["different popup document", [{...realPopupContext, documentId: "different-document"}]],
  ["different extension URL", [{...realPopupContext, documentUrl: POPUP_URL.replace("popup", "other")}]],
  ["context attached to a tab", [{...realPopupContext, tabId: 7}]],
  ["missing context ID", [{...realPopupContext, contextId: undefined}]],
  ["empty context ID", [{...realPopupContext, contextId: ""}]],
]) {
  test(`browser context gate rejects ${description}`, async (t) => {
    const h = await harness({contexts}); t.after(() => h.cleanup());
    h.unlock();
    await until(() => h.popupMessages.some((message) => message.ok === false), "untrusted context must settle");
    assert.equal(h.nativeRequests.length, 0, "no credential command before Chrome confirms the popup context");
    assert.equal(h.fills().length, 0);
    publicRepliesContainNoSecrets(h);
  });
}

test("a verified focused popup permits its otherwise unfocused parent window", async (t) => {
  const h = await harness({focused: false}); t.after(() => h.cleanup());
  h.fill();
  await until(() => h.popupMessages.some((message) => message.op === "filled"), "real popup focus control must settle");
  assert.ok(h.contextQueries >= 3, "Chrome context is revalidated after binding and for the focus challenge");
  assert.equal(h.popupMessages.filter((message) => message.op === "check_focus").length, 1);
  assert.equal(h.fills().length, 1);
  assert.ok(h.calls("lock").length >= 1);
  publicRepliesContainNoSecrets(h);
});

for (const [description, options] of [
  ["wrong parent window", {popupWindowId: 6}],
  ["unfocused popup", {popupFocused: false}],
]) {
  test(`focus challenge rejects ${description}`, async (t) => {
    const h = await harness({focused: false, ...options}); t.after(() => h.cleanup());
    h.fill();
    await until(() => h.popupMessages.some((message) => message.ok === false), "focus refusal must settle");
    assert.equal(h.fills().length, 0);
    assert.ok(h.calls("lock").length >= 1, "refused fill releases the native session");
    assert.ok(h.credentials.every((credential) => credential.password === "" && credential.username === ""));
    publicRepliesContainNoSecrets(h);
  });
}

test("lost popup context between initial request and focus challenge rejects", async (t) => {
  const options = {focused: false};
  const h = await harness(options); t.after(() => h.cleanup());
  const gate = h.hold("runtime.getContexts.3");
  h.fill(); await gate.arrived;
  assert.equal(h.credentials.length, 1, "the initial trusted request succeeded before the popup context changed");
  options.contexts = [];
  gate.release();
  await until(() => h.popupMessages.some((message) => message.ok === false), "missing second context must settle");
  assert.equal(h.fills().length, 0);
  assert.equal(h.popupMessages.filter((message) => message.op === "check_focus").length, 0);
  assert.ok(h.calls("lock").length >= 1);
  publicRepliesContainNoSecrets(h);
});

test("focus challenge timeout rejects and ignores a late response", async (t) => {
  const h = await harness({focused: false, autoFocusResponse: false}); t.after(() => h.cleanup());
  h.fill();
  await until(() => h.popupMessages.some((message) => message.op === "check_focus"), "focus challenge must be issued");
  h.advance(501); h.fireTimer(500);
  await until(() => h.popupMessages.some((message) => message.ok === false), "focus timeout must settle");
  h.focusReply();
  for (let i = 0; i < 3; i++) await turn();
  assert.equal(h.fills().length, 0);
  assert.ok(h.calls("lock").length >= 1);
  publicRepliesContainNoSecrets(h);
});

test("focus response checks elapsed deadline even before its delayed timer runs", async (t) => {
  const h = await harness({focused: false, autoFocusResponse: false}); t.after(() => h.cleanup());
  h.fill();
  await until(() => h.popupMessages.some((message) => message.op === "check_focus"), "focus challenge must be issued");
  h.advance(500); h.focusReply();
  await until(() => h.popupMessages.some((message) => message.ok === false), "expired focus reply must settle");
  assert.equal(h.fills().length, 0);
  assert.ok(h.calls("lock").length >= 1);
  publicRepliesContainNoSecrets(h);
});

test("an unrelated challenge ID cannot authorize focus", async (t) => {
  const h = await harness({focused: false, autoFocusResponse: false}); t.after(() => h.cleanup());
  h.fill();
  await until(() => h.popupMessages.some((message) => message.op === "check_focus"), "focus challenge must be issued");
  const request = h.popupMessages.find((message) => message.op === "check_focus");
  h.focusReply({request_id: request.request_id + 1});
  for (let i = 0; i < 3; i++) await turn();
  assert.equal(h.fills().length, 0, "unmatched reply is ignored");
  h.advance(501); h.fireTimer(500);
  await until(() => h.popupMessages.some((message) => message.ok === false), "unmatched reply cannot prevent timeout");
  assert.equal(h.fills().length, 0);
  publicRepliesContainNoSecrets(h);
});

for (const revoke of ["explicit lock", "popup closure", "native lease expiry"]) {
  test(`pending focus reply cannot survive ${revoke}`, async (t) => {
    const h = await harness({focused: false, autoFocusResponse: false}); t.after(() => h.cleanup());
    h.fill();
    await until(() => h.popupMessages.some((message) => message.op === "check_focus"), "focus challenge must be issued");
    if (revoke === "explicit lock") h.lock();
    else if (revoke === "popup closure") h.popup.disconnect();
    else h.advance(2001);
    h.focusReply();
    await until(() => h.credentials.every((credential) => credential.password === "" && credential.username === ""),
      "revoked credential must be released");
    if (revoke === "explicit lock") {
      await until(() => h.popupMessages.some((message) => message.op === "locked" && message.ok), "lock must settle");
    }
    assert.equal(h.fills().length, 0);
    assert.ok(!h.popupMessages.some((message) => message.op === "filled"));
    if (revoke === "popup closure") assert.equal(h.native.closed, true);
    publicRepliesContainNoSecrets(h);
  });
}

test("native denial still closes the fill authorization session", async (t) => {
  const h = await harness({rejectNativeOp: "fill"}); t.after(() => h.cleanup());
  h.fill();
  await until(() => h.popupMessages.some((message) => message.ok === false), "native denial must settle");
  assert.ok(h.calls("lock").length >= 1);
  assert.equal(h.fills().length, 0);
  publicRepliesContainNoSecrets(h);
});

test("a renderer refusal still wipes the credential and locks", async (t) => {
  const h = await harness({rendererFilled: false}); t.after(() => h.cleanup());
  h.fill();
  await until(() => h.popupMessages.some((message) => message.ok === false), "renderer refusal must settle");
  assert.equal(h.fills().length, 1);
  assert.ok(h.calls("lock").length >= 1);
  assert.ok(h.credentials.every((credential) => credential.password === "" && credential.username === ""));
  assert.ok(!h.popupMessages.some((message) => message.op === "filled"));
  publicRepliesContainNoSecrets(h);
});

test("lease timer wipes fields while a Chrome check is still pending", async (t) => {
  const h = await harness(); t.after(() => h.cleanup());
  const gate = h.hold("windows.get");
  h.fill(); await gate.arrived;
  assert.ok(h.credentials.some((credential) => credential.password === SYNTHETIC_PASSWORD));
  h.advance(2001); h.fireTimer(1990);
  assert.ok(h.credentials.every((credential) => credential.password === "" && credential.username === ""),
    "timer clears retained fields without requiring the blocked Chrome call to settle");
  assert.equal(h.fills().length, 0);
  gate.release();
  await until(() => h.popupMessages.some((message) => message.ok === false), "expired check must settle as rejected");
  assert.equal(h.fills().length, 0);
  assert.ok(h.calls("lock").length >= 1);
  publicRepliesContainNoSecrets(h);
});

test("lease expiry cannot acknowledge lock ahead of an accepted Chrome dispatch", async (t) => {
  const h = await harness(); t.after(() => h.cleanup());
  const gate = h.hold("scripting.fill");
  h.fill(); await gate.arrived;
  assert.equal(h.fills().length, 1);
  h.advance(2001); h.fireTimer(1990); h.lock();
  for (let i = 0; i < 5; i++) await turn();
  assert.ok(h.credentials.every((credential) => credential.password === "" && credential.username === ""));
  assert.ok(!h.popupMessages.some((message) => message.op === "locked"),
    "expiry does not resolve a still outstanding dispatch");
  gate.release();
  await until(() => h.popupMessages.some((message) => message.op === "locked" && message.ok), "lock follows actual dispatch outcome");
  assert.ok(h.trace.indexOf("fill.completed") < h.trace.indexOf("popup.locked"));
  assert.ok(!h.popupMessages.some((message) => message.op === "filled"));
  publicRepliesContainNoSecrets(h);
});

test("a sender without documentId binds once to the unique real popup context", async (t) => {
  const h = await harness({sender: {id: EXTENSION_ID, url: POPUP_URL}, focused: false});
  t.after(() => h.cleanup());
  h.fill();
  await until(() => h.popupMessages.some((message) => message.op === "filled"), "Chrome popup without sender document ID must settle");
  assert.equal(h.fills().length, 1);
  assert.ok(h.contextQueries >= 3);
  publicRepliesContainNoSecrets(h);
});

for (const [description, contexts] of [
  ["missing", []],
  ["ambiguous", [realPopupContext, {...realPopupContext, documentId: "other-document", contextId: "other-context"}]],
  ["non-popup", [{...realPopupContext, contextType: "TAB"}]],
  ["missing document ID", [{...realPopupContext, documentId: undefined}]],
  ["missing context ID", [{...realPopupContext, contextId: undefined}]],
]) {
  test(`sender without documentId rejects ${description} registry binding`, async (t) => {
    const h = await harness({sender: {id: EXTENSION_ID, url: POPUP_URL}, contexts});
    t.after(() => h.cleanup());
    h.unlock();
    await until(() => h.popupMessages.some((message) => message.ok === false), "unbound sender must be refused");
    assert.equal(h.calls("unlock").length, 0);
    assert.equal(h.fills().length, 0);
    publicRepliesContainNoSecrets(h);
  });
}

for (const [description, contexts] of [
  ["document replacement", [{...realPopupContext, documentId: "replacement-document"}]],
  ["context replacement", [{...realPopupContext, contextId: "replacement-context"}]],
  ["context disappearance", []],
]) {
  test(`an established popup binding rejects ${description} without rebinding`, async (t) => {
    const options = {sender: {id: EXTENSION_ID, url: POPUP_URL}};
    const h = await harness(options); t.after(() => h.cleanup());
    const gate = h.hold("runtime.getContexts.2");
    h.unlock(); await gate.arrived;
    options.contexts = contexts;
    gate.release();
    await until(() => h.popupMessages.some((message) => message.ok === false), "changed bound context must refuse authorization");
    assert.equal(h.calls("unlock").length, 0);
    assert.equal(h.fills().length, 0);
    publicRepliesContainNoSecrets(h);
  });
}
