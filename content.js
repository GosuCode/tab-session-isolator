// Runs in every tab. Only fills credentials when the background confirms this
// tab belongs to a saved profile and the page is on the profile's domain.

(function () {
  if (window.top !== window) return;

  const FIELD_SELECTOR =
    'input:not([type="hidden"]):not([type="submit"]):not([type="button"]):not([type="checkbox"]):not([type="radio"]):not([disabled]):not([readonly])';

  function isVisible(el) {
    return Boolean(el && (el.offsetWidth || el.offsetHeight || el.getClientRects().length));
  }

  function visible(selector) {
    return Array.from(document.querySelectorAll(selector)).filter(isVisible);
  }

  function findPasswordField() {
    return visible('input[type="password"]:not([disabled]):not([readonly])')[0] || null;
  }

  function findEmailField(passwordField) {
    const direct = visible(
      'input[type="email"]:not([disabled]):not([readonly]), ' +
        'input[autocomplete="username"]:not([disabled]):not([readonly]), ' +
        'input[name*="email" i]:not([disabled]):not([readonly]), ' +
        'input[id*="email" i]:not([disabled]):not([readonly])'
    )[0];
    if (direct) return direct;

    const byUser = visible(
      'input[name*="user" i]:not([disabled]):not([readonly]), ' +
        'input[id*="user" i]:not([disabled]):not([readonly])'
    )[0];
    if (byUser) return byUser;

    const texts = visible(FIELD_SELECTOR).filter((el) => {
      const type = (el.getAttribute("type") || "text").toLowerCase();
      return type === "text" || type === "email";
    });
    if (passwordField) {
      const before = texts.filter(
        (el) => el.compareDocumentPosition(passwordField) & Node.DOCUMENT_POSITION_FOLLOWING
      );
      if (before.length) return before[before.length - 1];
    }
    return texts[0] || null;
  }

  // Set value through the native setter so frameworks (React/Vue) notice it.
  function setValue(el, value) {
    const proto =
      el instanceof HTMLTextAreaElement ? HTMLTextAreaElement.prototype : HTMLInputElement.prototype;
    const setter = Object.getOwnPropertyDescriptor(proto, "value").set;
    setter.call(el, value);
    el.dispatchEvent(new Event("input", { bubbles: true }));
    el.dispatchEvent(new Event("change", { bubbles: true }));
  }

  function sameSite(host, domain) {
    if (!domain) return true;
    const strip = (h) => h.replace(/^www\./i, "").toLowerCase();
    return strip(host) === strip(domain) || host.toLowerCase().endsWith("." + domain.toLowerCase());
  }

  function fill(credentials) {
    if (!credentials) return false;
    if (!/^https?:$/.test(location.protocol)) return false;
    if (!sameSite(location.hostname, credentials.domain)) return false;

    const passwordField = findPasswordField();
    const emailField = findEmailField(passwordField);
    let filled = false;

    if (emailField && credentials.email && !emailField.value) {
      setValue(emailField, credentials.email);
      filled = true;
    }
    if (passwordField && credentials.password && !passwordField.value) {
      setValue(passwordField, credentials.password);
      filled = true;
    }
    return filled;
  }

  function attempt(credentials) {
    if (fill(credentials)) return;

    // Login forms are often rendered late; keep trying briefly.
    let tries = 0;
    const timer = setInterval(() => {
      if (fill(credentials) || ++tries >= 20) clearInterval(timer);
    }, 500);

    const observer = new MutationObserver(() => {
      if (fill(credentials)) observer.disconnect();
    });
    observer.observe(document.documentElement || document, {
      childList: true,
      subtree: true
    });
    setTimeout(() => observer.disconnect(), 15000);
  }

  chrome.runtime.sendMessage({ action: "GET_CREDENTIALS" }, (credentials) => {
    if (chrome.runtime.lastError) return;
    attempt(credentials);
  });
})();
