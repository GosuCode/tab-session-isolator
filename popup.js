document.addEventListener("DOMContentLoaded", async () => {
  const form = document.getElementById("createForm");
  const nameInput = document.getElementById("profileName");
  const emailInput = document.getElementById("email");
  const passwordInput = document.getElementById("password");
  const togglePassword = document.getElementById("togglePassword");
  const eyeShow = document.getElementById("eyeShow");
  const eyeHide = document.getElementById("eyeHide");
  const urlInput = document.getElementById("url");
  const createBtn = document.getElementById("createBtn");
  const cancelBtn = document.getElementById("cancelBtn");
  const profileList = document.getElementById("profileList");
  const searchInput = document.getElementById("profileSearch");
  const vaultSetupSection = document.getElementById("vaultSetup");
  const vaultLockedSection = document.getElementById("vaultLocked");
  const vaultUnlockedBar = document.getElementById("vaultUnlockedBar");
  const vaultSetupForm = document.getElementById("vaultSetupForm");
  const vaultUnlockForm = document.getElementById("vaultUnlockForm");
  const vaultLockBtn = document.getElementById("vaultLockBtn");
  const toast = document.getElementById("toast");
  const toastMsg = document.getElementById("toastMsg");
  const toastClose = document.getElementById("toastClose");

  let toastTimer = null;
  function showToast(message) {
    toastMsg.textContent = message;
    toast.hidden = false;
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => { toast.hidden = true; }, 6000);
  }
  toastClose.addEventListener("click", () => {
    clearTimeout(toastTimer);
    toast.hidden = true;
  });

  let editingId = null;
  let allProfiles = {};
  // Domains the user has manually collapsed. Multi-profile domains start expanded.
  const collapsedDomains = new Set();

  function sendMessage(payload) {
    return new Promise((resolve) => chrome.runtime.sendMessage(payload, resolve));
  }

  // Reflects vault state in the UI and gates the create/edit form on it —
  // saving a password requires an unlocked vault key in the background.
  async function refreshVaultUI() {
    const status = await sendMessage({ action: "VAULT_STATUS" });
    const exists = Boolean(status && status.exists);
    const unlocked = Boolean(status && status.unlocked);
    vaultSetupSection.hidden = exists;
    vaultLockedSection.hidden = !(exists && !unlocked);
    vaultUnlockedBar.hidden = !(exists && unlocked);
    form.hidden = !(exists && unlocked);
    return exists && unlocked;
  }

  vaultSetupForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    const pw = document.getElementById("vaultNewPassword").value;
    const confirmPw = document.getElementById("vaultConfirmPassword").value;
    if (pw.length < 8) {
      showToast("Master password must be at least 8 characters.");
      return;
    }
    if (pw !== confirmPw) {
      showToast("Passwords do not match.");
      return;
    }
    const res = await sendMessage({ action: "VAULT_SETUP", password: pw });
    if (!res || !res.success) {
      showToast("Could not set master password.");
      return;
    }
    vaultSetupForm.reset();
    await refreshVaultUI();
    loadProfiles();
  });

  vaultUnlockForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    const pw = document.getElementById("vaultUnlockPassword").value;
    const res = await sendMessage({ action: "VAULT_UNLOCK", password: pw });
    if (!res || !res.success) {
      showToast(res && res.error === "wrong-password" ? "Incorrect master password." : "Could not unlock vault.");
      return;
    }
    vaultUnlockForm.reset();
    await refreshVaultUI();
  });

  vaultLockBtn.addEventListener("click", async () => {
    await sendMessage({ action: "VAULT_LOCK" });
    setEditMode(null);
    await refreshVaultUI();
  });

  function resetPasswordVisibility() {
    passwordInput.type = "password";
    eyeShow.hidden = false;
    eyeHide.hidden = true;
    togglePassword.setAttribute("aria-pressed", "false");
    togglePassword.setAttribute("aria-label", "Show password");
  }

  async function setEditMode(profile) {
    editingId = profile ? profile.id : null;
    if (profile) {
      nameInput.value = profile.name || "";
      emailInput.value = profile.email || "";
      passwordInput.value = "";
      urlInput.value = profile.url || "";
      createBtn.textContent = "Save changes";
      cancelBtn.hidden = false;
      nameInput.focus();
      if (profile.passwordEnc) {
        const res = await sendMessage({ action: "GET_PROFILE_PASSWORD", profileId: profile.id });
        if (res && res.success) {
          passwordInput.value = res.password;
        } else {
          showToast("Vault is locked. Unlock it to edit the saved password.");
        }
      }
    } else {
      form.reset();
      createBtn.textContent = "Create profile";
      cancelBtn.hidden = true;
    }
    resetPasswordVisibility();
  }

  cancelBtn.addEventListener("click", () => setEditMode(null));

  togglePassword.addEventListener("click", () => {
    const reveal = passwordInput.type === "password";
    passwordInput.type = reveal ? "text" : "password";
    togglePassword.setAttribute("aria-pressed", String(reveal));
    togglePassword.setAttribute("aria-label", reveal ? "Hide password" : "Show password");
    eyeShow.hidden = reveal;
    eyeHide.hidden = !reveal;
  });

  // Keep only the base URL (scheme + host + port), dropping any path/query/hash.
  function normalizeBaseUrl(raw) {
    let value = (raw || "").trim();
    if (!value) return "";
    if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(value)) value = "https://" + value;
    try {
      const parsed = new URL(value);
      if (parsed.protocol !== "http:" && parsed.protocol !== "https:") return "";
      return parsed.origin;
    } catch (e) {
      return "";
    }
  }

  // Prefill the URL field with the current tab's base URL when it is a normal
  // web page. The user can freely edit or replace it.
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  try {
    const parsed = tab && tab.url ? new URL(tab.url) : null;
    if (parsed && (parsed.protocol === "http:" || parsed.protocol === "https:")) {
      urlInput.value = parsed.origin;
    }
  } catch (e) {
    // Ignore unparseable URLs (chrome://, about:, file://, ...).
  }

  function matchesSearch(profile, query) {
    if (!query) return true;
    const haystack = [profile.name, profile.email, profile.domain, profile.url]
      .join(" ")
      .toLowerCase();
    return haystack.includes(query);
  }

  function buildCaret() {
    const caret = document.createElementNS("http://www.w3.org/2000/svg", "svg");
    caret.setAttribute("class", "caret");
    caret.setAttribute("viewBox", "0 0 24 24");
    caret.setAttribute("fill", "none");
    caret.setAttribute("stroke", "currentColor");
    caret.setAttribute("stroke-width", "2.5");
    caret.setAttribute("stroke-linecap", "round");
    caret.setAttribute("stroke-linejoin", "round");
    const path = document.createElementNS("http://www.w3.org/2000/svg", "path");
    path.setAttribute("d", "M6 9l6 6 6-6");
    caret.appendChild(path);
    return caret;
  }

  function renderProfiles() {
    const query = searchInput.value.trim().toLowerCase();
    profileList.textContent = "";
    const list = Object.values(allProfiles || {}).filter((p) => matchesSearch(p, query));

    if (list.length === 0) {
      const empty = document.createElement("div");
      empty.className = "empty";
      empty.textContent = query ? "No profiles match your search." : "No profiles yet.";
      profileList.appendChild(empty);
      return;
    }

    const grouped = {};
    list.forEach((p) => {
      const key = p.domain || "No domain";
      if (!grouped[key]) grouped[key] = [];
      grouped[key].push(p);
    });

    Object.entries(grouped).forEach(([domain, items]) => {
      const group = document.createElement("div");
      group.className = "domain";

      const hasMultiple = items.length > 1;
      // While searching, force matching groups open so results stay visible.
      const isCollapsed = hasMultiple && !query && collapsedDomains.has(domain);

      const itemsEl = document.createElement("div");
      itemsEl.className = "domain-items" + (isCollapsed ? " collapsed" : "");

      if (hasMultiple) {
        const header = document.createElement("button");
        header.type = "button";
        header.className = "domain-header";
        header.setAttribute("aria-expanded", String(!isCollapsed));
        header.appendChild(buildCaret());

        const nameEl = document.createElement("span");
        nameEl.className = "domain-name";
        nameEl.textContent = domain;
        header.appendChild(nameEl);

        const count = document.createElement("span");
        count.className = "count";
        count.textContent = items.length;
        header.appendChild(count);

        header.addEventListener("click", () => {
          if (collapsedDomains.has(domain)) {
            collapsedDomains.delete(domain);
          } else {
            collapsedDomains.add(domain);
          }
          renderProfiles();
        });

        group.appendChild(header);
      } else {
        const header = document.createElement("div");
        header.className = "domain-header single";
        const nameEl = document.createElement("span");
        nameEl.className = "domain-name";
        nameEl.textContent = domain;
        header.appendChild(nameEl);
        group.appendChild(header);
      }

      items.forEach((p) => {
        const card = document.createElement("div");
        card.className = "profile";

        const top = document.createElement("div");
        top.className = "profile-top";

        const name = document.createElement("span");
        name.className = "profile-name";
        name.textContent = p.name;

        const actions = document.createElement("div");
        actions.className = "actions";

        const edit = document.createElement("button");
        edit.className = "edit";
        edit.textContent = "Edit";
        edit.addEventListener("click", () => setEditMode(p));

        const launch = document.createElement("button");
        launch.className = "launch";
        launch.textContent = "Launch";
        launch.addEventListener("click", () => {
          chrome.runtime.sendMessage(
            { action: "LAUNCH_PROFILE", profileId: p.id },
            (response) => reportError(response)
          );
        });

        actions.append(edit, launch);
        top.append(name, actions);
        card.appendChild(top);

        if (p.email) {
          const meta = document.createElement("div");
          meta.className = "profile-meta";
          meta.textContent = p.email;
          card.appendChild(meta);
        }
        if (p.url) {
          const meta = document.createElement("div");
          meta.className = "profile-meta";
          meta.textContent = p.url;
          card.appendChild(meta);
        }

        itemsEl.appendChild(card);
      });

      group.appendChild(itemsEl);
      profileList.appendChild(group);
    });
  }

  function loadProfiles() {
    chrome.runtime.sendMessage({ action: "GET_PROFILES" }, (profiles) => {
      allProfiles = profiles || {};
      renderProfiles();
    });
  }

  searchInput.addEventListener("input", renderProfiles);

  function reportError(response) {
    if (!response || response.success !== false) return;
    if (response.error === "containers-disabled") {
      showToast(
        "Firefox containers are disabled. Set privacy.userContext.enabled to true " +
          "in about:config, then restart Firefox."
      );
    } else if (response.error === "vault-locked") {
      showToast("Vault is locked. Unlock it above before saving credentials.");
    } else if (response.error === "vault-not-setup") {
      showToast("Set a master password above before saving credentials.");
    } else {
      showToast("Could not complete the request: " + response.error);
    }
  }

  form.addEventListener("submit", (event) => {
    event.preventDefault();

    const name = nameInput.value.trim();
    const email = emailInput.value.trim();
    const password = passwordInput.value;
    const url = normalizeBaseUrl(urlInput.value);

    if (!name) {
      showToast("Enter a profile name.");
      return;
    }
    if (!url) {
      showToast("Enter a valid http(s) URL.");
      return;
    }

    createBtn.disabled = true;
    const payload = editingId
      ? { action: "EDIT_PROFILE", profileId: editingId, name, email, password, url }
      : { action: "CREATE_PROFILE", profileName: name, email, password, url };

    chrome.runtime.sendMessage(payload, (response) => {
      createBtn.disabled = false;
      reportError(response);
      if (response && response.success) {
        setEditMode(null);
        loadProfiles();
      }
    });
  });

  refreshVaultUI();
  loadProfiles();
});
