// Functions run in an ISOLATED world in exactly one browser-supplied document.
// No page-origin messages are accepted by the extension. The page receives
// credentials only at this explicitly requested, revalidated fill boundary.
export function inspectLogin(expectedUrl) {
  if (window.top !== window || document.visibilityState !== "visible" || location.href !== expectedUrl || location.protocol !== "https:") {
    throw new Error("page_changed_or_inactive");
  }
  const visible = (input) => {
    const style = getComputedStyle(input);
    const rect = input.getBoundingClientRect();
    return !input.disabled && !input.readOnly && input.isConnected && input.checkVisibility({checkOpacity: true, checkVisibilityCSS: true}) && style.visibility === "visible" && style.display !== "none" && style.opacity !== "0" && rect.width > 0 && rect.height > 0 && rect.bottom > 0 && rect.right > 0 && rect.top < innerHeight && rect.left < innerWidth;
  };
  const passwords = [...document.querySelectorAll('input[type="password"]')].filter(visible);
  if (passwords.length !== 1) throw new Error("ambiguous_password_form");
  const password = passwords[0];
  const form = password.form;
  if (!form || form.method.toLowerCase() !== "post" || new URL(form.action, location.href).origin !== location.origin || form.target && form.target !== "_self") {
    throw new Error("form_target_rejected");
  }
  const users = [...form.elements].filter((e) => e instanceof HTMLInputElement && ["text", "email"].includes(e.type) && visible(e));
  if (users.length !== 1) throw new Error("ambiguous_username_field");
  for (const button of [...document.querySelectorAll('button, input[type="submit"], input[type="image"]')].filter((button) => button.form === form)) {
    if ((button.hasAttribute("formaction") && new URL(button.formAction, location.href).origin !== location.origin)
      || (button.hasAttribute("formmethod") && button.formMethod.toLowerCase() !== "post")
      || (button.hasAttribute("formtarget") && button.formTarget && button.formTarget !== "_self")) {
      throw new Error("submit_target_rejected");
    }
  }
  return {url: location.href, origin: location.origin, formAction: form.action, usernameName: users[0].name, passwordName: password.name};
}

export function fillLogin(expected, username, password) {
  // Keep this validation inside the injected function: executeScript functions
  // do not retain their module closure. No asynchronous yield occurs between
  // the final validation and assignment.
  if (window.top !== window || document.visibilityState !== "visible" || !document.hasFocus() || location.href !== expected.url || location.origin !== expected.origin || location.protocol !== "https:") {
    throw new Error("page_changed_or_inactive");
  }
  if (!Number.isFinite(expected.notAfter) || performance.timeOrigin + performance.now() >= expected.notAfter) throw new Error("fill_authorization_expired");
  const visible = (input) => {
    const style = getComputedStyle(input); const rect = input.getBoundingClientRect();
    return !input.disabled && !input.readOnly && input.isConnected && input.checkVisibility({checkOpacity: true, checkVisibilityCSS: true}) && style.visibility === "visible" && style.display !== "none" && style.opacity !== "0" && rect.width > 0 && rect.height > 0 && rect.bottom > 0 && rect.right > 0 && rect.top < innerHeight && rect.left < innerWidth;
  };
  const passwords = [...document.querySelectorAll('input[type="password"]')].filter(visible);
  if (passwords.length !== 1) throw new Error("ambiguous_password_form");
  const p = passwords[0], form = p.form;
  if (!form || form.action !== expected.formAction || new URL(form.action, location.href).origin !== expected.origin || form.method.toLowerCase() !== "post" || form.target && form.target !== "_self") throw new Error("form_changed");
  const users = [...form.elements].filter((e) => e instanceof HTMLInputElement && ["text", "email"].includes(e.type) && visible(e));
  if (users.length !== 1 || users[0].name !== expected.usernameName || p.name !== expected.passwordName) throw new Error("fields_changed");
  for (const button of [...document.querySelectorAll('button, input[type="submit"], input[type="image"]')].filter((button) => button.form === form)) {
    if ((button.hasAttribute("formaction") && new URL(button.formAction, location.href).origin !== expected.origin)
      || (button.hasAttribute("formmethod") && button.formMethod.toLowerCase() !== "post")
      || (button.hasAttribute("formtarget") && button.formTarget && button.formTarget !== "_self")) throw new Error("submit_target_rejected");
  }
  const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value").set;
  if (performance.timeOrigin + performance.now() >= expected.notAfter) throw new Error("fill_authorization_expired");
  if (!document.hasFocus()) throw new Error("page_changed_or_inactive");
  setter.call(users[0], username);
  setter.call(p, password);
  // No automatic submit. Page event handlers may read the filled credential;
  // that is the intended exact-origin final-use boundary.
  users[0].dispatchEvent(new Event("input", {bubbles: true}));
  p.dispatchEvent(new Event("input", {bubbles: true}));
  return {filled: true, submitted: false};
}
