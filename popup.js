document.addEventListener("DOMContentLoaded", async () => {
  const formPanel = document.getElementById("createFormPanel");
  const formHeading = document.getElementById("formHeading");
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
  const createForCurrentBtn = document.getElementById("createForCurrentBtn");
  const profilesSection = document.getElementById("profilesSection");
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
  let vaultReady = false;
  let formOpen = false;
  // Domains the user has manually collapsed. Multi-profile domains start expanded.
  const collapsedDomains = new Set();

  function sendMessage(payload) {
    return new Promise((resolve) => chrome.runtime.sendMessage(payload, resolve));
  }

  // Switches between the profiles list and the create/edit form as two full
  // views of the popup, rather than showing both stacked at once.
  function updateFormPanelVisibility() {
    formPanel.hidden = !(vaultReady && formOpen);
    if (vaultReady) profilesSection.hidden = formOpen;
  }

  // Reflects vault state in the UI and gates the create/edit form on it —
  // saving a password requires an unlocked vault key in the background.
  async function refreshVaultUI() {
    const status = await sendMessage({ action: "VAULT_STATUS" });
    const exists = Boolean(status && status.exists);
    const unlocked = Boolean(status && status.unlocked);
    const locked = exists && !unlocked;
    vaultSetupSection.hidden = exists;
    vaultLockedSection.hidden = !locked;
    vaultUnlockedBar.hidden = !(exists && unlocked);
    // While locked, the vault-locked panel is the only thing shown — no
    // browsing/creating profiles until the user unlocks it.
    profilesSection.hidden = locked;
    vaultReady = exists && unlocked;
    if (locked) closeForm();
    updateFormPanelVisibility();
    return vaultReady;
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
    closeForm();
    await refreshVaultUI();
  });

  // Setting the `.hidden` IDL property doesn't reliably reflect to the
  // `hidden` content attribute on these dynamically-built SVG icons, so the
  // `[hidden]` CSS rule never fires and both icons stay visible. Toggle the
  // attribute directly instead.
  function setHidden(el, hidden) {
    if (hidden) el.setAttribute("hidden", "");
    else el.removeAttribute("hidden");
  }

  function resetPasswordVisibility() {
    passwordInput.type = "password";
    setHidden(eyeShow, false);
    setHidden(eyeHide, true);
    togglePassword.setAttribute("aria-pressed", "false");
    togglePassword.setAttribute("aria-label", "Show password");
  }

  // prefillUrl: base URL to seed the form with (current tab, or a domain's
  // existing origin) when opening it for a brand-new profile.
  async function openForm(prefillUrl) {
    editingId = null;
    form.reset();
    if (prefillUrl) urlInput.value = prefillUrl;
    createBtn.textContent = "Create profile";
    formHeading.textContent = "New profile";
    resetPasswordVisibility();
    formOpen = true;
    updateFormPanelVisibility();
    nameInput.focus();
  }

  function closeForm() {
    editingId = null;
    form.reset();
    createBtn.textContent = "Create profile";
    formHeading.textContent = "New profile";
    resetPasswordVisibility();
    formOpen = false;
    updateFormPanelVisibility();
  }

  async function editProfile(profile) {
    editingId = profile.id;
    nameInput.value = profile.name || "";
    emailInput.value = profile.email || "";
    passwordInput.value = "";
    urlInput.value = profile.url || "";
    createBtn.textContent = "Save changes";
    formHeading.textContent = "Edit " + profile.name;
    resetPasswordVisibility();
    formOpen = true;
    updateFormPanelVisibility();
    nameInput.focus();

    if (profile.passwordEnc) {
      const res = await sendMessage({ action: "GET_PROFILE_PASSWORD", profileId: profile.id });
      if (res && res.success) {
        passwordInput.value = res.password;
      } else {
        showToast("Vault is locked. Unlock it to edit the saved password.");
      }
    }
  }

  cancelBtn.addEventListener("click", () => closeForm());
  createForCurrentBtn.addEventListener("click", () => openForm(currentTabOrigin));

  togglePassword.addEventListener("click", () => {
    const reveal = passwordInput.type === "password";
    passwordInput.type = reveal ? "text" : "password";
    togglePassword.setAttribute("aria-pressed", String(reveal));
    togglePassword.setAttribute("aria-label", reveal ? "Hide password" : "Show password");
    setHidden(eyeShow, reveal);
    setHidden(eyeHide, !reveal);
  });

  function eyeIconSvg(crossedOut) {
    const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
    svg.setAttribute("viewBox", "0 0 24 24");
    svg.setAttribute("fill", "none");
    svg.setAttribute("stroke", "currentColor");
    svg.setAttribute("stroke-width", "2");
    svg.setAttribute("stroke-linecap", "round");
    svg.setAttribute("stroke-linejoin", "round");
    svg.innerHTML = crossedOut
      ? '<path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94"></path>' +
        '<path d="M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19"></path>' +
        '<path d="M14.12 14.12a3 3 0 1 1-4.24-4.24"></path><line x1="1" y1="1" x2="23" y2="23"></line>'
      : '<path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path><circle cx="12" cy="12" r="3"></circle>';
    return svg;
  }

  // Wraps a plain password input with the same show/hide eye toggle used on
  // the profile password field, without duplicating the SVG markup in HTML.
  function addPasswordToggle(input) {
    const wrap = document.createElement("span");
    wrap.className = "pw";
    input.parentNode.insertBefore(wrap, input);
    wrap.appendChild(input);

    const btn = document.createElement("button");
    btn.type = "button";
    btn.className = "eye";
    btn.setAttribute("aria-label", "Show password");
    btn.setAttribute("aria-pressed", "false");

    const show = eyeIconSvg(false);
    const hide = eyeIconSvg(true);
    setHidden(hide, true);
    btn.append(show, hide);
    wrap.appendChild(btn);

    btn.addEventListener("click", () => {
      const reveal = input.type === "password";
      input.type = reveal ? "text" : "password";
      btn.setAttribute("aria-pressed", String(reveal));
      btn.setAttribute("aria-label", reveal ? "Hide password" : "Show password");
      setHidden(show, reveal);
      setHidden(hide, !reveal);
    });
  }

  [
    document.getElementById("vaultNewPassword"),
    document.getElementById("vaultConfirmPassword"),
    document.getElementById("vaultUnlockPassword")
  ].forEach(addPasswordToggle);

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

  // Base URL of the tab the popup was opened from, used to prefill the
  // "create profile for current site" flow. Empty for non-http(s) pages.
  let currentTabOrigin = "";
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  try {
    const parsed = tab && tab.url ? new URL(tab.url) : null;
    if (parsed && (parsed.protocol === "http:" || parsed.protocol === "https:")) {
      currentTabOrigin = parsed.origin;
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

  function buildGlobeIcon() {
    const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
    svg.setAttribute("class", "globe");
    svg.setAttribute("viewBox", "0 0 24 24");
    svg.setAttribute("width", "11");
    svg.setAttribute("height", "11");
    svg.setAttribute("fill", "none");
    svg.setAttribute("stroke", "currentColor");
    svg.setAttribute("stroke-width", "2");
    svg.setAttribute("stroke-linecap", "round");
    const circle = document.createElementNS("http://www.w3.org/2000/svg", "circle");
    circle.setAttribute("cx", "12");
    circle.setAttribute("cy", "12");
    circle.setAttribute("r", "9");
    const ellipse = document.createElementNS("http://www.w3.org/2000/svg", "ellipse");
    ellipse.setAttribute("cx", "12");
    ellipse.setAttribute("cy", "12");
    ellipse.setAttribute("rx", "4");
    ellipse.setAttribute("ry", "9");
    const line = document.createElementNS("http://www.w3.org/2000/svg", "line");
    line.setAttribute("x1", "3");
    line.setAttribute("y1", "12");
    line.setAttribute("x2", "21");
    line.setAttribute("y2", "12");
    svg.append(circle, ellipse, line);
    return svg;
  }

  function launchProfile(profileId) {
    chrome.runtime.sendMessage({ action: "LAUNCH_PROFILE", profileId }, (response) => reportError(response));
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

      const headerRow = document.createElement("div");
      headerRow.className = "domain-header-row";

      if (hasMultiple) {
        const header = document.createElement("button");
        header.type = "button";
        header.className = "domain-header";
        header.setAttribute("aria-expanded", String(!isCollapsed));
        header.appendChild(buildCaret());
        header.appendChild(buildGlobeIcon());

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

        headerRow.appendChild(header);
      } else {
        const header = document.createElement("div");
        header.className = "domain-header single";
        header.appendChild(buildGlobeIcon());
        const nameEl = document.createElement("span");
        nameEl.className = "domain-name";
        nameEl.textContent = domain;
        header.appendChild(nameEl);
        headerRow.appendChild(header);
      }

      const addTabBtn = document.createElement("button");
      addTabBtn.type = "button";
      addTabBtn.className = "add-tab-btn";
      addTabBtn.textContent = "+ Add tab";
      addTabBtn.addEventListener("click", () => {
        const prefill = items[0].url || (domain !== "No domain" ? "https://" + domain : "");
        openForm(prefill);
      });
      headerRow.appendChild(addTabBtn);

      group.appendChild(headerRow);

      const itemsEl = document.createElement("div");
      itemsEl.className = "domain-items" + (isCollapsed ? " collapsed" : "");

      items.forEach((p) => {
        const row = document.createElement("div");
        row.className = "tree-row";

        const main = document.createElement("div");
        main.className = "profile-main";

        const dot = document.createElement("span");
        dot.className = "profile-dot";
        dot.style.background = p.color || "var(--muted)";
        main.appendChild(dot);

        const text = document.createElement("div");
        text.className = "profile-text";

        const name = document.createElement("div");
        name.className = "profile-name";
        name.textContent = p.name;
        text.appendChild(name);

        if (p.email) {
          const meta = document.createElement("div");
          meta.className = "profile-meta";
          meta.textContent = p.email;
          text.appendChild(meta);
        }

        main.appendChild(text);
        row.appendChild(main);

        const actions = document.createElement("div");
        actions.className = "actions";

        const edit = document.createElement("button");
        edit.className = "edit";
        edit.textContent = "Edit";
        edit.addEventListener("click", () => editProfile(p));

        const launch = document.createElement("button");
        launch.className = "launch";
        launch.textContent = "Launch";
        launch.addEventListener("click", () => launchProfile(p.id));

        actions.append(edit, launch);
        row.appendChild(actions);

        itemsEl.appendChild(row);
      });

      if (hasMultiple) {
        const launchAllRow = document.createElement("div");
        launchAllRow.className = "tree-row";

        const launchAllBtn = document.createElement("button");
        launchAllBtn.type = "button";
        launchAllBtn.className = "launch-all-btn";
        launchAllBtn.textContent = "Launch all " + items.length + " tabs";
        launchAllBtn.addEventListener("click", () => {
          items.forEach((p) => launchProfile(p.id));
        });

        launchAllRow.appendChild(launchAllBtn);
        itemsEl.appendChild(launchAllRow);
      }

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
        closeForm();
        loadProfiles();
      }
    });
  });

  refreshVaultUI();
  loadProfiles();
});
