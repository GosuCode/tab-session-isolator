// Runs in every tab. Only fills credentials when the background confirms this
// tab belongs to a saved profile and the page is on the profile's domain.

(function () {
  if (window.top !== window) return;

  // Cheap early-out for paths that are clearly not a login page, so we skip
  // the credential request and DOM-watching entirely. Not the real fix (the
  // password-field gate below is) — just avoids wasted work on obvious
  // non-login pages. The login-ish exception keeps nested paths like
  // /support/login from being skipped by the "support" match.
  const SKIP_PATH_RE =
    /\b(checkout|cart|contact|about|blog|support|help|terms|privacy|pricing|docs?|search|products?|categor(?:y|ies)|articles?|news|faq)\b/i;
  const LOGIN_PATH_RE = /\b(login|log-in|signin|sign-in|signup|sign-up|register|auth|session|account|sso)\b/i;
  if (SKIP_PATH_RE.test(location.pathname) && !LOGIN_PATH_RE.test(location.pathname)) return;

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

  // Scoped to the password field's own <form> (falling back to the whole
  // document only when the password field isn't inside one) so an unrelated
  // email input elsewhere on the page — a newsletter box, a contact form —
  // never gets caught up in the login form's autofill.
  function findEmailField(passwordField) {
    const scope = (passwordField && passwordField.closest("form")) || document;
    const visibleIn = (selector) => Array.from(scope.querySelectorAll(selector)).filter(isVisible);

    const direct = visibleIn(
      'input[type="email"]:not([disabled]):not([readonly]), ' +
        'input[autocomplete="username"]:not([disabled]):not([readonly]), ' +
        'input[name*="email" i]:not([disabled]):not([readonly]), ' +
        'input[id*="email" i]:not([disabled]):not([readonly])'
    )[0];
    if (direct) return direct;

    const byUser = visibleIn(
      'input[name*="user" i]:not([disabled]):not([readonly]), ' +
        'input[id*="user" i]:not([disabled]):not([readonly])'
    )[0];
    if (byUser) return byUser;

    const texts = visibleIn(FIELD_SELECTOR).filter((el) => {
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

    // A visible password field is the actual signal this is a login form —
    // without one, leave every field on the page alone.
    const passwordField = findPasswordField();
    if (!passwordField) return false;

    const emailField = findEmailField(passwordField);
    let filled = false;

    if (emailField && credentials.email && !emailField.value) {
      setValue(emailField, credentials.email);
      filled = true;
    }
    if (credentials.password && !passwordField.value) {
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
