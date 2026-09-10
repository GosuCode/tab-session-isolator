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

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.action === "CREATE_PROFILE") {
    handleCreateProfile(message.profileName, message.email, message.password, message.url)
      .then(sendResponse)
      .catch((e) => sendResponse({ success: false, error: errorCode(e) }));
    return true; // Async response
  }

  if (message.action === "LAUNCH_PROFILE") {
    handleLaunchProfile(message.profileId)
      .then(sendResponse)
      .catch((e) => sendResponse({ success: false, error: errorCode(e) }));
    return true;
  }

  if (message.action === "EDIT_PROFILE") {
    handleEditProfile(message.profileId, message.name, message.email, message.password, message.url)
      .then(sendResponse)
      .catch((e) => sendResponse({ success: false, error: errorCode(e) }));
    return true;
  }

  if (message.action === "GET_CREDENTIALS") {
    const tabId = sender.tab && sender.tab.id;
    getTabProfile(tabId).then((profileId) => {
      if (!profileId) {
        sendResponse(null);
        return;
      }
      browser.storage.local.get("profiles").then((res) => {
        const profile = (res.profiles || {})[profileId];
        if (!profile) {
          sendResponse(null);
          return;
        }
        sendResponse({
          email: profile.email || "",
          password: profile.password || "",
          domain: profile.domain || ""
        });
      });
    });
    return true;
  }

  if (message.action === "GET_PROFILES") {
    browser.storage.local.get("profiles").then((res) => {
      sendResponse(res.profiles || {});
    });
    return true;
  }
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

  const baseUrl = originOf(url) || url;
  const profileId = "prof_" + Date.now();
  const index = Math.floor(Math.random() * CONTAINER_COLORS.length);

  const cookieStoreId = await createContainer(name, CONTAINER_COLORS[index]);

  const profile = {
    id: profileId,
    name,
    email: email || "",
    password: password || "",
    url: baseUrl,
    domain: hostnameOf(baseUrl),
    color: BADGE_COLORS[index],
    containerColor: CONTAINER_COLORS[index],
    cookieStoreId
  };

  const { profiles = {} } = await browser.storage.local.get("profiles");
  profiles[profileId] = profile;
  await browser.storage.local.set({ profiles });

  const tab = await browser.tabs.create({ url: baseUrl, cookieStoreId });
  await setTabProfile(tab.id, profileId);
  updateTabBadge(tab.id, name, profile.color);

  return { success: true, profileId, tabId: tab.id };
}

// Launch existing profile in a new isolated tab
async function handleLaunchProfile(profileId) {
  if (containersDisabled()) return { success: false, error: "containers-disabled" };

  const { profiles = {} } = await browser.storage.local.get("profiles");
  const profile = profiles[profileId];
  if (!profile) return { success: false, error: "not-found" };

  // Older profiles predate containers, or the container was removed by the user.
  if (!(await containerStillExists(profile.cookieStoreId))) {
    profile.cookieStoreId = await createContainer(
      profile.name,
      profile.containerColor || "blue"
    );
    profiles[profileId] = profile;
    await browser.storage.local.set({ profiles });
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
  const { profiles = {} } = await browser.storage.local.get("profiles");
  const profile = profiles[profileId];
  if (!profile) return { success: false, error: "not-found" };

  const baseUrl = originOf(url) || url;
  profile.name = name;
  profile.email = email || "";
  profile.password = password || "";
  profile.url = baseUrl;
  profile.domain = hostnameOf(baseUrl);

  // Keep the container label in sync with the profile name.
  if (profile.cookieStoreId && !containersDisabled()) {
    try {
      await browser.contextualIdentities.update(profile.cookieStoreId, { name });
    } catch (e) {
      // Container may have been removed; it is recreated on next launch.
    }
  }

  profiles[profileId] = profile;
  await browser.storage.local.set({ profiles });

  // Refresh the badge on any open tabs that belong to this profile.
  if (profile.cookieStoreId && !containersDisabled()) {
    try {
      const tabs = await browser.tabs.query({ cookieStoreId: profile.cookieStoreId });
      tabs.forEach((t) => updateTabBadge(t.id, profile.name, profile.color));
    } catch (e) {
      // Ignore badge refresh failures.
    }
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
