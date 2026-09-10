// Firefox-only. Each profile gets its own contextual identity (container),
// so cookies and localStorage are isolated per profile by the browser.

const CONTAINER_COLORS = ["blue", "green", "purple", "orange", "red", "pink"];
const BADGE_COLORS = ["#3B82F6", "#10B981", "#8B5CF6", "#F59E0B", "#EF4444", "#EC4899"];

// Map tab IDs to profile IDs so a content script can ask for its credentials.
// Kept in storage.session so it survives event-page suspension.
const TAB_PROFILES_KEY = "activeTabProfiles";
let tabProfilesCache = null;

async function getTabProfiles() {
  if (!tabProfilesCache) {
    const res = await browser.storage.session.get(TAB_PROFILES_KEY);
    tabProfilesCache = res[TAB_PROFILES_KEY] || {};
  }
  return tabProfilesCache;
}

async function setTabProfile(tabId, profileId) {
  const map = await getTabProfiles();
  map[tabId] = profileId;
  await browser.storage.session.set({ [TAB_PROFILES_KEY]: map });
}

async function getTabProfile(tabId) {
  const map = await getTabProfiles();
  return map[tabId];
}

async function removeTabProfile(tabId) {
  const map = await getTabProfiles();
  delete map[tabId];
  await browser.storage.session.set({ [TAB_PROFILES_KEY]: map });
}

const containersDisabled = () =>
  !browser.contextualIdentities || !browser.cookies;

// --- Profile storage -------------------------------------------------------

async function getProfiles() {
  const res = await browser.storage.local.get("profiles");
  return res.profiles || {};
}

async function saveProfiles(profiles) {
  await browser.storage.local.set({ profiles });
}

async function trySilently(fn) {
  try {
    await fn();
  } catch (e) {
    // Ignore: caller treats this as best-effort.
  }
}

// --- Password vault -------------------------------------------------------
// Saved passwords are encrypted at rest with a key derived from a
// user-chosen master password (PBKDF2 -> AES-GCM). The derived key is
// cached in storage.session (memory-only, cleared on browser restart) so
// the user only unlocks once per browser session.

const VAULT_META_KEY = "vaultMeta"; // storage.local: { salt, check: {iv, ct} }
const VAULT_SESSION_KEY = "vaultKeyRaw"; // storage.session: base64 raw AES-256 key
const VAULT_CHECK_PLAINTEXT = "tab-session-isolator-vault-check";
const PBKDF2_ITERATIONS = 300000;

let cachedCryptoKey = null;

function bufToB64(buf) {
  return btoa(String.fromCharCode(...new Uint8Array(buf)));
}

function b64ToBuf(b64) {
  const bin = atob(b64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes.buffer;
}

async function deriveKeyFromPassword(password, saltB64) {
  const baseKey = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(password),
    "PBKDF2",
    false,
    ["deriveKey"]
  );
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt: b64ToBuf(saltB64), iterations: PBKDF2_ITERATIONS, hash: "SHA-256" },
    baseKey,
    { name: "AES-GCM", length: 256 },
    true,
    ["encrypt", "decrypt"]
  );
}

async function encryptString(key, plaintext) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, new TextEncoder().encode(plaintext));
  return { iv: bufToB64(iv), ct: bufToB64(ct) };
}

async function decryptString(key, { iv, ct }) {
  const plainBuf = await crypto.subtle.decrypt({ name: "AES-GCM", iv: b64ToBuf(iv) }, key, b64ToBuf(ct));
  return new TextDecoder().decode(plainBuf);
}

async function encryptPasswordIfProvided(key, password) {
  return password ? await encryptString(key, password) : null;
}

async function getVaultMeta() {
  const res = await browser.storage.local.get(VAULT_META_KEY);
  return res[VAULT_META_KEY] || null;
}

async function getCachedKey() {
  if (cachedCryptoKey) return cachedCryptoKey;
  const res = await browser.storage.session.get(VAULT_SESSION_KEY);
  const raw = res[VAULT_SESSION_KEY];
  if (!raw) return null;
  cachedCryptoKey = await crypto.subtle.importKey("raw", b64ToBuf(raw), "AES-GCM", true, [
    "encrypt",
    "decrypt"
  ]);
  return cachedCryptoKey;
}

async function cacheKey(key) {
  cachedCryptoKey = key;
  const raw = await crypto.subtle.exportKey("raw", key);
  await browser.storage.session.set({ [VAULT_SESSION_KEY]: bufToB64(raw) });
}

async function clearCachedKey() {
  cachedCryptoKey = null;
  await browser.storage.session.remove(VAULT_SESSION_KEY);
}

// Create the vault for the first time and migrate any legacy plaintext
// passwords (saved before this feature existed) into encrypted form.
async function setupVault(password) {
  const saltB64 = bufToB64(crypto.getRandomValues(new Uint8Array(16)));
  const key = await deriveKeyFromPassword(password, saltB64);
  const check = await encryptString(key, VAULT_CHECK_PLAINTEXT);
  await browser.storage.local.set({ [VAULT_META_KEY]: { salt: saltB64, check } });
  await cacheKey(key);

  const profiles = await getProfiles();
  let changed = false;
  for (const profile of Object.values(profiles)) {
    if (typeof profile.password === "string" && profile.password) {
      profile.passwordEnc = await encryptString(key, profile.password);
      delete profile.password;
      changed = true;
    }
  }
  if (changed) await saveProfiles(profiles);
}

async function unlockVault(password) {
  const meta = await getVaultMeta();
  if (!meta) return { success: false, error: "vault-not-setup" };
  const key = await deriveKeyFromPassword(password, meta.salt);
  try {
    const check = await decryptString(key, meta.check);
    if (check !== VAULT_CHECK_PLAINTEXT) throw new Error("mismatch");
  } catch (e) {
    return { success: false, error: "wrong-password" };
  }
  await cacheKey(key);
  return { success: true };
}

// No key cached (vault locked or never unlocked this session): skip
// silently, the page just doesn't get autofilled until the user
// unlocks the vault from the popup.
async function handleGetCredentials(tabId) {
  const profileId = await getTabProfile(tabId);
  if (!profileId) return null;

  const profile = (await getProfiles())[profileId];
  if (!profile) return null;

  const key = await getCachedKey();
  let password = "";
  if (key && profile.passwordEnc) {
    try {
      password = await decryptString(key, profile.passwordEnc);
    } catch (e) {
      password = "";
    }
  }
  return { email: profile.email || "", password, domain: profile.domain || "" };
}

async function handleGetProfilePassword(profileId) {
  const profile = (await getProfiles())[profileId];
  if (!profile) return { success: false, error: "not-found" };

  const key = await getCachedKey();
  if (!key) return { success: false, error: "vault-locked" };

  try {
    const password = profile.passwordEnc ? await decryptString(key, profile.passwordEnc) : "";
    return { success: true, password };
  } catch (e) {
    return { success: false, error: "decrypt-failed" };
  }
}

async function handleVaultStatus() {
  const [meta, key] = await Promise.all([getVaultMeta(), getCachedKey()]);
  return { exists: !!meta, unlocked: !!key };
}

// Each handler takes (message, sender) and resolves to the response payload.
// The listener below owns all response/error plumbing so handlers stay pure.
const messageHandlers = {
  CREATE_PROFILE: (message) =>
    handleCreateProfile(message.profileName, message.email, message.password, message.url),
  LAUNCH_PROFILE: (message) => handleLaunchProfile(message.profileId),
  EDIT_PROFILE: (message) =>
    handleEditProfile(message.profileId, message.name, message.email, message.password, message.url),
  GET_CREDENTIALS: (message, sender) => handleGetCredentials(sender.tab && sender.tab.id),
  GET_PROFILE_PASSWORD: (message) => handleGetProfilePassword(message.profileId),
  VAULT_STATUS: () => handleVaultStatus(),
  VAULT_SETUP: (message) => setupVault(message.password).then(() => ({ success: true })),
  VAULT_UNLOCK: (message) => unlockVault(message.password),
  VAULT_LOCK: () => clearCachedKey().then(() => ({ success: true })),
  GET_PROFILES: () => getProfiles()
};

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  const handler = messageHandlers[message.action];
  if (!handler) return false;

  Promise.resolve(handler(message, sender))
    .then(sendResponse)
    .catch((e) => sendResponse({ success: false, error: errorCode(e) }));
  return true; // Async response
});

function errorCode(e) {
  const text = String((e && e.message) || e);
  if (containersDisabled() || /contextualIdentit/i.test(text)) {
    return "containers-disabled";
  }
  return text;
}

function hostnameOf(url) {
  try {
    return new URL(url).hostname;
  } catch (e) {
    return "";
  }
}

function originOf(url) {
  try {
    const parsed = new URL(url);
    if (parsed.protocol !== "http:" && parsed.protocol !== "https:") return "";
    return parsed.origin;
  } catch (e) {
    return "";
  }
}

async function containerStillExists(cookieStoreId) {
  if (!cookieStoreId) return false;
  try {
    await browser.contextualIdentities.get(cookieStoreId);
    return true;
  } catch (e) {
    return false;
  }
}

async function createContainer(name, color) {
  const identity = await browser.contextualIdentities.create({
    name,
    color: CONTAINER_COLORS.includes(color) ? color : "blue",
    icon: "fingerprint"
  });
  return identity.cookieStoreId;
}

// Create new profile and open its isolated tab
async function handleCreateProfile(name, email, password, url) {
  if (containersDisabled()) return { success: false, error: "containers-disabled" };

  const vaultMeta = await getVaultMeta();
  if (!vaultMeta) return { success: false, error: "vault-not-setup" };
  const key = await getCachedKey();
  if (!key) return { success: false, error: "vault-locked" };

  const baseUrl = originOf(url) || url;
  const profileId = "prof_" + Date.now();
  const index = Math.floor(Math.random() * CONTAINER_COLORS.length);

  const cookieStoreId = await createContainer(name, CONTAINER_COLORS[index]);

  const profile = {
    id: profileId,
    name,
    email: email || "",
    passwordEnc: await encryptPasswordIfProvided(key, password),
    url: baseUrl,
    domain: hostnameOf(baseUrl),
    color: BADGE_COLORS[index],
    containerColor: CONTAINER_COLORS[index],
    cookieStoreId
  };

  const profiles = await getProfiles();
  profiles[profileId] = profile;
  await saveProfiles(profiles);

  const tab = await browser.tabs.create({ url: baseUrl, cookieStoreId });
  await setTabProfile(tab.id, profileId);
  updateTabBadge(tab.id, name, profile.color);

  return { success: true, profileId, tabId: tab.id };
}

// Launch existing profile in a new isolated tab
async function handleLaunchProfile(profileId) {
  if (containersDisabled()) return { success: false, error: "containers-disabled" };

  const profiles = await getProfiles();
  const profile = profiles[profileId];
  if (!profile) return { success: false, error: "not-found" };

  // Older profiles predate containers, or the container was removed by the user.
  if (!(await containerStillExists(profile.cookieStoreId))) {
    profile.cookieStoreId = await createContainer(
      profile.name,
      profile.containerColor || "blue"
    );
    profiles[profileId] = profile;
    await saveProfiles(profiles);
  }

  const targetUrl =
    profile.url || (profile.domain ? `https://${profile.domain}` : "about:blank");
  const tab = await browser.tabs.create({ url: targetUrl, cookieStoreId: profile.cookieStoreId });
  await setTabProfile(tab.id, profileId);
  updateTabBadge(tab.id, profile.name, profile.color);

  return { success: true, tabId: tab.id };
}

// Edit an existing profile's details
async function handleEditProfile(profileId, name, email, password, url) {
  const profiles = await getProfiles();
  const profile = profiles[profileId];
  if (!profile) return { success: false, error: "not-found" };

  const key = await getCachedKey();
  if (!key) return { success: false, error: "vault-locked" };

  const baseUrl = originOf(url) || url;
  profile.name = name;
  profile.email = email || "";
  profile.passwordEnc = await encryptPasswordIfProvided(key, password);
  delete profile.password;
  profile.url = baseUrl;
  profile.domain = hostnameOf(baseUrl);

  // Keep the container label in sync with the profile name.
  if (profile.cookieStoreId && !containersDisabled()) {
    // Container may have been removed; it is recreated on next launch.
    await trySilently(() => browser.contextualIdentities.update(profile.cookieStoreId, { name }));
  }

  profiles[profileId] = profile;
  await saveProfiles(profiles);

  // Refresh the badge on any open tabs that belong to this profile.
  if (profile.cookieStoreId && !containersDisabled()) {
    await trySilently(async () => {
      const tabs = await browser.tabs.query({ cookieStoreId: profile.cookieStoreId });
      tabs.forEach((t) => updateTabBadge(t.id, profile.name, profile.color));
    });
  }

  return { success: true, profileId };
}

// Update visual badge on tab icon
function updateTabBadge(tabId, text, color) {
  const shortText = text.slice(0, 4).toUpperCase();
  browser.action.setBadgeText({ tabId, text: shortText });
  browser.action.setBadgeBackgroundColor({ tabId, color });
}

// Drop the tab -> profile mapping when a tab closes.
browser.tabs.onRemoved.addListener((tabId) => {
  removeTabProfile(tabId);
});
