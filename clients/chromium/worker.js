import {inspectLogin, fillLogin} from "./fill.js";

const HOST = "org.heptabao.personal_vault";

export async function currentContext() {
  const tabs = await chrome.tabs.query({active: true, lastFocusedWindow: true});
  const tab = tabs[0];
  if (!tab || !tab.id || !tab.url || new URL(tab.url).protocol !== "https:") throw new Error("https_page_required");
  const result = await chrome.scripting.executeScript({target: {tabId: tab.id, frameIds: [0]}, world: "ISOLATED", func: inspectLogin, args: [tab.url]});
  if (result.length !== 1 || result[0].frameId !== 0 || !result[0].documentId || !result[0].result) throw new Error("page_rejected");
  return {tabId: tab.id, documentId: result[0].documentId, ...result[0].result};
}

export async function applyFill(context, credential, stillAuthorized = () => true, deadline = performance.now() + 1000, popupFocused = async () => false) {
  if (!stillAuthorized()) throw new Error("fill_cancelled");
  if (credential.origin !== context.origin || typeof credential.username !== "string" || typeof credential.password !== "string") throw new Error("credential_origin_rejected");
  const tab = await chrome.tabs.get(context.tabId);
  if (!stillAuthorized()) throw new Error("fill_cancelled");
  const window = await chrome.windows.get(tab.windowId);
  if (!stillAuthorized()) throw new Error("fill_cancelled");
  if (!tab.active || tab.url !== context.url) throw new Error("page_changed");
  // Chrome can report the parent window unfocused while its real action popup
  // owns focus. Require a fresh reply from that authenticated popup in this
  // case; a visible background tab alone is never sufficient authorization.
  if (!window.focused && !await popupFocused(tab.windowId)) throw new Error("page_changed");
  if (!stillAuthorized()) throw new Error("fill_cancelled");
  const result = await chrome.scripting.executeScript({target: {tabId: context.tabId, documentIds: [context.documentId]}, world: "ISOLATED", func: fillLogin, args: [{...context, notAfter: performance.timeOrigin + deadline}, credential.username, credential.password]});
  if (result.length !== 1 || result[0].documentId !== context.documentId || result[0].result?.filled !== true) throw new Error("fill_rejected");
  return result[0].result;
}

chrome.runtime.onConnect.addListener((popup) => {
  // A webpage, content script, external extension or arbitrary extension URL
  // cannot use this handler. There is no externally_connectable surface.
  const popupUrl = chrome.runtime.getURL("popup.html");
  const senderDocumentId = popup.sender?.documentId;
  if (popup.name !== "vault-popup" || popup.sender?.id !== chrome.runtime.id || popup.sender?.url !== popupUrl || popup.sender?.tab || (senderDocumentId !== undefined && (typeof senderDocumentId !== "string" || !senderDocumentId))) {
    popup.disconnect(); return;
  }
  const native = chrome.runtime.connectNative(HOST);
  const pending = new Map(); const focusPending = new Map(); let nextId = 1; let nextFocusId = 1; let busy = false; let closed = false; let nativeGone = false; let epoch = 0; let locksPending = 0; let activeWork = Promise.resolve();
  function isPopup(context) {
    return context?.contextType === "POPUP" && context.documentUrl === popupUrl && context.tabId === -1 && typeof context.documentId === "string" && !!context.documentId && typeof context.contextId === "string" && !!context.contextId;
  }
  // Some real Chrome action-popup ports omit MessageSender.documentId. Bind
  // this exact extension-page port once to the browser's unique POPUP registry
  // entry instead. Never accept an identity supplied in a popup message, and
  // never rebind an old port when a later popup replaces its original document.
  const popupBinding = Promise.resolve().then(async () => {
    const filter = {contextTypes: ["POPUP"], documentUrls: [popupUrl]};
    if (senderDocumentId !== undefined) filter.documentIds = [senderDocumentId];
    const contexts = await chrome.runtime.getContexts(filter);
    if (closed || contexts.length !== 1 || !isPopup(contexts[0]) || (senderDocumentId !== undefined && contexts[0].documentId !== senderDocumentId)) return null;
    return {documentId: contexts[0].documentId, contextId: contexts[0].contextId};
  }).catch(() => null);
  async function trustedPopup() {
    const binding = await popupBinding;
    if (closed || !binding) return false;
    const contexts = await chrome.runtime.getContexts({contextTypes: ["POPUP"], documentIds: [binding.documentId]});
    return !closed && contexts.length === 1 && isPopup(contexts[0]) && contexts[0].documentId === binding.documentId && contexts[0].contextId === binding.contextId;
  }
  async function popupFocus(windowId, stillAuthorized) {
    if (!await trustedPopup() || !stillAuthorized()) return false;
    return new Promise((resolve) => {
      const id = nextFocusId++;
      const timeout = setTimeout(() => { focusPending.delete(id); resolve(false); }, 500);
      focusPending.set(id, {resolve, timeout, windowId, stillAuthorized, notAfter: performance.now() + 500});
      popup.postMessage({ok: true, op: "check_focus", request_id: id});
    });
  }
  function cancelFocus() {
    for (const waiter of focusPending.values()) { clearTimeout(waiter.timeout); waiter.resolve(false); }
    focusPending.clear();
  }
  function nativeCall(request) {
    if (closed || nativeGone) return Promise.reject(new Error("native_disconnected"));
    return new Promise((resolve, reject) => {
      const id = nextId++;
      const timeout = setTimeout(() => { pending.delete(id); reject(new Error("native_deadline")); native.disconnect(); }, 15000);
      pending.set(id, {resolve, reject, timeout});
      try { native.postMessage({id, request}); }
      catch { pending.delete(id); clearTimeout(timeout); reject(new Error("native_disconnected")); }
    });
  }
  native.onMessage.addListener((message) => {
    const waiter = pending.get(message.id); if (!waiter) return;
    pending.delete(message.id); clearTimeout(waiter.timeout);
    if (message.ok === true) waiter.resolve(message.result); else waiter.reject(new Error("vault_request_rejected"));
  });
  native.onDisconnect.addListener(() => {
    nativeGone = true;
    for (const waiter of pending.values()) { clearTimeout(waiter.timeout); waiter.reject(new Error("native_disconnected")); }
    pending.clear();
    cancelFocus();
    if (!closed) { popup.postMessage({ok: false, error: "vault_locked_or_unavailable"}); popup.disconnect(); }
  });
  popup.onDisconnect.addListener(() => { closed = true; epoch++; cancelFocus(); native.disconnect(); });
  popup.onMessage.addListener((message) => {
    if (closed) return;
    if (message?.op === "focus_response") {
      const waiter = focusPending.get(message.request_id); if (!waiter) return;
      focusPending.delete(message.request_id); clearTimeout(waiter.timeout);
      waiter.resolve(message.focused === true && message.window_id === waiter.windowId && performance.now() < waiter.notAfter && waiter.stillAuthorized());
      return;
    }
    if (message?.op === "lock") {
      epoch++;
      locksPending++;
      // A lock is never dropped because a fill is busy. If the browser already
      // accepted a fill dispatch, await its outcome before acknowledging lock.
      const previous = activeWork;
      activeWork = (async () => {
        try {
          await previous;
          await nativeCall({op: "lock"});
          if (!closed) popup.postMessage({ok: true, op: "locked"});
        } catch { if (!closed) popup.postMessage({ok: false, error: "lock_unconfirmed"}); }
        finally { locksPending--; }
      })();
      return;
    }
    if (busy || locksPending) return;
    busy = true;
    const ticket = epoch;
    const stillAuthorized = () => !closed && epoch === ticket;
    activeWork = (async () => { try {
      if (!await trustedPopup() || !stillAuthorized()) throw new Error("popup_context_rejected");
      if (message?.op === "unlock" && typeof message.password === "string" && message.password.length <= 4096) {
        const password = message.password; message.password = "";
        await nativeCall({op: "unlock", password});
        if (!stillAuthorized()) throw new Error("cancelled");
        const context = await currentContext();
        if (!stillAuthorized()) throw new Error("cancelled");
        const items = await nativeCall({op: "list", origin: context.origin});
        if (stillAuthorized()) popup.postMessage({ok: true, op: "list", origin: context.origin, items});
      } else if (message?.op === "fill" && typeof message.item_id === "string") {
        let expiry; let credential;
        try {
          const context = await currentContext();
          if (!stillAuthorized()) throw new Error("cancelled");
          const requestStarted = performance.now();
          credential = await nativeCall({op: "fill", item_id: message.item_id, origin: context.origin, top_frame: true});
          const budget = credential.valid_for_ms;
          if (!Number.isInteger(budget) || budget <= 0 || budget > 2000) throw new Error("fill_lease_rejected");
          const deadline = requestStarted + budget - 10;
          let expired = false;
          const fillAuthorized = () => stillAuthorized() && !expired && Number.isInteger(budget) && budget > 0 && budget <= 2000 && performance.now() < deadline;
          // Clear retained fields at expiry even if a Chrome API is pending.
          // Do not race an accepted dispatch to completion: lock confirmation
          // must still await the browser's actual dispatch outcome.
          expiry = setTimeout(() => { expired = true; credential.username = ""; credential.password = ""; }, Math.max(0, deadline - performance.now()));
          await applyFill(context, credential, fillAuthorized, deadline, (windowId) => popupFocus(windowId, fillAuthorized));
        } finally {
          clearTimeout(expiry);
          if (credential) { credential.username = ""; credential.password = ""; }
          await nativeCall({op: "lock"});
        }
        if (stillAuthorized()) popup.postMessage({ok: true, op: "filled"});
      } else throw new Error("request_rejected");
    } catch {
      // Never forward native errors, URLs, request bodies or plaintext fields.
      if (!closed && epoch === ticket) popup.postMessage({ok: false, error: "request_rejected_or_locked"});
    } finally { busy = false; } })();
  });
});
