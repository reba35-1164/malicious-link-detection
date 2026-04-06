const STORAGE_KEYS = {
  enabled: "extensionEnabled",
  redirectCount: "redirectCount",
  blockedRedirectCount: "blockedRedirectCount",
  legacyBlockList: "blockList",
  remoteBlockList: "remoteBlockList",
  customBlockList: "customBlockList",
  remoteLastUpdatedAt: "remoteLastUpdatedAt",
  allowList: "allowList",
};

const DEFAULTS = {
  extensionEnabled: true,
  redirectCount: 0,
  blockedRedirectCount: 0,
  remoteBlockList: [],
  customBlockList: [],
  remoteLastUpdatedAt: 0,
  allowList: [],
};

const INTERACTION_WINDOW_MS = 15000;
const BYPASS_WINDOW_MS = 5 * 60 * 1000;
const BLOCK_EVENT_DEDUP_WINDOW_MS = 2000;
const REMOTE_REFRESH_INTERVAL_MS = 7 * 24 * 60 * 60 * 1000;
const REMOTE_REFRESH_ALARM = "refreshRemoteBlockList";
const REMOTE_REFRESH_PERIOD_MINUTES = 7 * 24 * 60;

const REMOTE_DOMAIN_LIST_URLS = [
  "https://raw.githubusercontent.com/romainmarcoux/malicious-domains/main/full-domains-aa.txt",
  "https://raw.githubusercontent.com/romainmarcoux/malicious-domains/main/full-domains-ab.txt",
  "https://raw.githubusercontent.com/romainmarcoux/malicious-domains/main/full-domains-ac.txt",
];

const tabInteractionTs = new Map();
const tabBypass = new Map();
const tabLastBlocked = new Map();

let remoteRefreshInFlight = null;
const cachedState = {
  extensionEnabled: true,
  remoteBlockList: [],
  customBlockList: [],
  blockList: [],
  allowList: [],
};

function safeParseUrl(url) {
  try {
    return new URL(url);
  } catch {
    return null;
  }
}

function normalizePattern(input) {
  if (!input || typeof input !== "string") {
    return "";
  }

  const raw = input.trim().toLowerCase();
  if (!raw) {
    return "";
  }

  const withScheme = raw.includes("://") ? raw : `https://${raw}`;
  const parsed = safeParseUrl(withScheme);
  if (parsed && parsed.hostname) {
    return parsed.hostname;
  }

  return raw.replace(/^\.+/, "").replace(/\/.*/, "");
}

function normalizeList(list) {
  if (!Array.isArray(list)) {
    return [];
  }

  const seen = new Set();
  const normalized = [];

  for (const entry of list) {
    const pattern = normalizePattern(entry);
    if (!pattern || seen.has(pattern)) {
      continue;
    }
    seen.add(pattern);
    normalized.push(pattern);
  }

  return normalized;
}

function unionLists(...lists) {
  const merged = [];
  const seen = new Set();

  for (const list of lists) {
    for (const entry of normalizeList(list)) {
      if (seen.has(entry)) {
        continue;
      }
      seen.add(entry);
      merged.push(entry);
    }
  }

  return merged;
}

function wildcardToRegex(pattern) {
  const escaped = pattern.replace(/[.+?^${}()|[\]\\]/g, "\\$&");
  return new RegExp(`^${escaped.replace(/\*/g, ".*")}$`, "i");
}

function matchesPattern(hostname, pattern) {
  if (!hostname || !pattern) {
    return false;
  }

  if (pattern === "*") {
    return true;
  }

  if (pattern.startsWith("*.")) {
    const base = pattern.slice(2);
    return hostname === base || hostname.endsWith(`.${base}`);
  }

  if (pattern.includes("*")) {
    return wildcardToRegex(pattern).test(hostname);
  }

  return hostname === pattern || hostname.endsWith(`.${pattern}`);
}

function hostInList(hostname, list) {
  return list.some((pattern) => matchesPattern(hostname, pattern));
}

function isHttpUrl(urlString) {
  const parsed = safeParseUrl(urlString);
  return !!parsed && (parsed.protocol === "http:" || parsed.protocol === "https:");
}

async function getState() {
  const stored = await chrome.storage.local.get(DEFAULTS);
  const remoteBlockList = normalizeList(stored.remoteBlockList);
  const customBlockList = normalizeList(stored.customBlockList);
  const blockList = unionLists(remoteBlockList, customBlockList);

  return {
    extensionEnabled: stored.extensionEnabled !== false,
    redirectCount: Number.isFinite(stored.redirectCount) ? stored.redirectCount : 0,
    blockedRedirectCount: Number.isFinite(stored.blockedRedirectCount)
      ? stored.blockedRedirectCount
      : 0,
    remoteBlockList,
    customBlockList,
    blockList,
    remoteLastUpdatedAt: Number.isFinite(stored.remoteLastUpdatedAt)
      ? stored.remoteLastUpdatedAt
      : 0,
    allowList: normalizeList(stored.allowList),
  };
}

async function incrementRedirectCount() {
  const state = await getState();
  await chrome.storage.local.set({ [STORAGE_KEYS.redirectCount]: state.redirectCount + 1 });
}

async function incrementBlockedRedirectCount() {
  const state = await getState();
  await chrome.storage.local.set({
    [STORAGE_KEYS.blockedRedirectCount]: state.blockedRedirectCount + 1,
  });
}

function updateCachedState(state) {
  cachedState.extensionEnabled = state.extensionEnabled !== false;
  cachedState.remoteBlockList = Array.isArray(state.remoteBlockList) ? state.remoteBlockList : [];
  cachedState.customBlockList = Array.isArray(state.customBlockList) ? state.customBlockList : [];
  cachedState.blockList = Array.isArray(state.blockList) ? state.blockList : [];
  cachedState.allowList = Array.isArray(state.allowList) ? state.allowList : [];
}

async function refreshCachedState() {
  const state = await getState();
  updateCachedState(state);
}

function shouldCountRedirect(tabId) {
  const interactionTs = tabInteractionTs.get(tabId);
  if (!interactionTs) {
    return false;
  }
  return Date.now() - interactionTs <= INTERACTION_WINDOW_MS;
}

function hasBypass(tabId, hostname) {
  const bypass = tabBypass.get(tabId);
  if (!bypass) {
    return false;
  }

  if (Date.now() > bypass.expiresAt) {
    tabBypass.delete(tabId);
    return false;
  }

  if (bypass.hostname !== hostname) {
    return false;
  }

  return true;
}

function shouldRecordBlock(tabId, blockedUrl) {
  const previous = tabLastBlocked.get(tabId);
  const now = Date.now();

  if (
    previous &&
    previous.url === blockedUrl &&
    now - previous.timestamp <= BLOCK_EVENT_DEDUP_WINDOW_MS
  ) {
    return false;
  }

  tabLastBlocked.set(tabId, { url: blockedUrl, timestamp: now });
  return true;
}

function openWarningPage(tabId, blockedUrl, sourceUrl) {
  const warningUrl = new URL(chrome.runtime.getURL("warning.html"));
  warningUrl.searchParams.set("target", blockedUrl);
  warningUrl.searchParams.set("source", sourceUrl || "");

  chrome.tabs.update(tabId, { url: warningUrl.toString() });

  if (shouldRecordBlock(tabId, blockedUrl)) {
    void incrementBlockedRedirectCount();
  }
}

async function migrateLegacyBlockListIfNeeded() {
  const stored = await chrome.storage.local.get({
    [STORAGE_KEYS.legacyBlockList]: [],
    [STORAGE_KEYS.customBlockList]: [],
  });

  const legacy = normalizeList(stored[STORAGE_KEYS.legacyBlockList]);
  const custom = normalizeList(stored[STORAGE_KEYS.customBlockList]);

  if (legacy.length > 0 && custom.length === 0) {
    await chrome.storage.local.set({ [STORAGE_KEYS.customBlockList]: legacy });
  }

  await chrome.storage.local.remove(STORAGE_KEYS.legacyBlockList);
}

async function refreshRemoteBlockList(options = {}) {
  if (remoteRefreshInFlight) {
    return remoteRefreshInFlight;
  }

  const { force = false } = options;

  remoteRefreshInFlight = (async () => {
    const state = await getState();
    const now = Date.now();
    const elapsed = now - state.remoteLastUpdatedAt;

    if (!force && state.remoteLastUpdatedAt > 0 && elapsed < REMOTE_REFRESH_INTERVAL_MS) {
      return { refreshed: false, reason: "not_due" };
    }

    const results = await Promise.allSettled(
      REMOTE_DOMAIN_LIST_URLS.map(async (url) => {
        const response = await fetch(url, { cache: "no-store" });
        if (!response.ok) {
          throw new Error(`Failed to fetch ${url} (${response.status})`);
        }

        const content = await response.text();
        return content
          .split(/\r?\n/)
          .map((line) => normalizePattern(line))
          .filter(Boolean);
      })
    );

    const nextRemoteList = [];
    for (const result of results) {
      if (result.status !== "fulfilled") {
        continue;
      }

      for (const domain of result.value) {
        nextRemoteList.push(domain);
      }
    }

    const normalized = normalizeList(nextRemoteList);
    if (normalized.length === 0) {
      throw new Error("Remote domain list refresh failed");
    }

    await chrome.storage.local.set({
      [STORAGE_KEYS.remoteBlockList]: normalized,
      [STORAGE_KEYS.remoteLastUpdatedAt]: now,
    });

    return { refreshed: true, count: normalized.length, updatedAt: now };
  })();

  try {
    return await remoteRefreshInFlight;
  } finally {
    remoteRefreshInFlight = null;
  }
}

async function ensureWeeklyRefreshAlarm() {
  chrome.alarms.create(REMOTE_REFRESH_ALARM, {
    periodInMinutes: REMOTE_REFRESH_PERIOD_MINUTES,
  });
}

async function initializeExtensionData(options = {}) {
  const { forceRefresh = false } = options;
  const state = await chrome.storage.local.get(DEFAULTS);

  await chrome.storage.local.set({
    [STORAGE_KEYS.enabled]: state.extensionEnabled !== false,
    [STORAGE_KEYS.redirectCount]: Number.isFinite(state.redirectCount) ? state.redirectCount : 0,
    [STORAGE_KEYS.blockedRedirectCount]: Number.isFinite(state.blockedRedirectCount)
      ? state.blockedRedirectCount
      : 0,
    [STORAGE_KEYS.remoteBlockList]: normalizeList(state.remoteBlockList),
    [STORAGE_KEYS.customBlockList]: normalizeList(state.customBlockList),
    [STORAGE_KEYS.remoteLastUpdatedAt]: Number.isFinite(state.remoteLastUpdatedAt)
      ? state.remoteLastUpdatedAt
      : 0,
    [STORAGE_KEYS.allowList]: normalizeList(state.allowList),
  });

  await migrateLegacyBlockListIfNeeded();
  await ensureWeeklyRefreshAlarm();

  try {
    await refreshRemoteBlockList({ force: forceRefresh });
  } catch {
    // Keep the previous list if refresh fails.
  }

  await refreshCachedState();
}

chrome.runtime.onInstalled.addListener(async () => {
  await initializeExtensionData({ forceRefresh: true });
});

chrome.runtime.onStartup.addListener(async () => {
  await initializeExtensionData({ forceRefresh: false });
});

chrome.alarms.onAlarm.addListener(async (alarm) => {
  if (!alarm || alarm.name !== REMOTE_REFRESH_ALARM) {
    return;
  }

  try {
    await refreshRemoteBlockList({ force: true });
  } catch {
    // Keep the previous list if refresh fails.
  }
});

chrome.webRequest.onBeforeRedirect.addListener((details) => {
  if (details.tabId < 0) {
    return;
  }

  if (!isHttpUrl(details.redirectUrl)) {
    return;
  }

  const state = cachedState;
  if (!state.extensionEnabled) {
    return;
  }

  const destination = safeParseUrl(details.redirectUrl);
  if (!destination || !destination.hostname) {
    return;
  }

  const hostname = destination.hostname.toLowerCase();

  if (hostInList(hostname, state.allowList)) {
    return;
  }

  if (shouldCountRedirect(details.tabId)) {
    void incrementRedirectCount();
  }

  if (hasBypass(details.tabId, hostname)) {
    return;
  }

  if (hostInList(hostname, state.blockList)) {
    openWarningPage(details.tabId, details.redirectUrl, details.url);
  }
}, { urls: ["<all_urls>"] });

chrome.webRequest.onBeforeRequest.addListener((details) => {
  if (details.tabId < 0 || details.type !== "main_frame") {
    return;
  }

  if (!isHttpUrl(details.url)) {
    return;
  }

  const state = cachedState;
  if (!state.extensionEnabled) {
    return;
  }

  const destination = safeParseUrl(details.url);
  if (!destination || !destination.hostname) {
    return;
  }

  const hostname = destination.hostname.toLowerCase();

  if (hostInList(hostname, state.allowList)) {
    return;
  }

  if (hasBypass(details.tabId, hostname)) {
    return;
  }

  if (hostInList(hostname, state.blockList)) {
    openWarningPage(details.tabId, details.url, details.initiator || "");
  }
}, { urls: ["<all_urls>"] });

chrome.webNavigation.onCommitted.addListener((details) => {
  if (details.tabId < 0 || details.frameId !== 0) {
    return;
  }

  if (!isHttpUrl(details.url)) {
    return;
  }

  const state = cachedState;
  if (!state.extensionEnabled) {
    return;
  }

  const destination = safeParseUrl(details.url);
  if (!destination || !destination.hostname) {
    return;
  }

  const hostname = destination.hostname.toLowerCase();

  if (hostInList(hostname, state.allowList)) {
    return;
  }

  if (hasBypass(details.tabId, hostname)) {
    return;
  }

  if (hostInList(hostname, state.blockList)) {
    openWarningPage(details.tabId, details.url, "");
  }
});

chrome.storage.onChanged.addListener((changes, areaName) => {
  if (areaName !== "local") {
    return;
  }

  if (changes.extensionEnabled) {
    cachedState.extensionEnabled = changes.extensionEnabled.newValue !== false;
  }

  if (changes.allowList) {
    cachedState.allowList = normalizeList(changes.allowList.newValue);
  }

  if (changes.remoteBlockList || changes.customBlockList || changes.blockList) {
    if (changes.remoteBlockList) {
      cachedState.remoteBlockList = normalizeList(changes.remoteBlockList.newValue);
    }

    if (changes.customBlockList) {
      cachedState.customBlockList = normalizeList(changes.customBlockList.newValue);
    }

    if (changes.blockList) {
      cachedState.blockList = normalizeList(changes.blockList.newValue);
      return;
    }

    cachedState.blockList = unionLists(cachedState.remoteBlockList, cachedState.customBlockList);
  }
});

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (!message || typeof message !== "object") {
    return;
  }

  if (message.type === "userInteraction") {
    const tabId = sender.tab?.id;
    if (typeof tabId === "number") {
      tabInteractionTs.set(tabId, Date.now());
    }
    return;
  }

  if (message.type === "getPopupState") {
    getState()
      .then((state) => {
        sendResponse({
          extensionEnabled: state.extensionEnabled,
          redirectCount: state.redirectCount,
          blockedRedirectCount: state.blockedRedirectCount,
          blockListCount: state.blockList.length,
          remoteBlockListCount: state.remoteBlockList.length,
          customBlockListCount: state.customBlockList.length,
          allowListCount: state.allowList.length,
          remoteLastUpdatedAt: state.remoteLastUpdatedAt,
        });
      })
      .catch(() => {
        sendResponse({
          extensionEnabled: true,
          redirectCount: 0,
          blockedRedirectCount: 0,
          blockListCount: 0,
          remoteBlockListCount: 0,
          customBlockListCount: 0,
          allowListCount: 0,
          remoteLastUpdatedAt: 0,
        });
      });
    return true;
  }

  if (message.type === "refreshThreatFeed") {
    refreshRemoteBlockList({ force: true })
      .then(async (refreshResult) => {
        const state = await getState();
        sendResponse({
          ok: true,
          refreshed: refreshResult?.refreshed === true,
          blockListCount: state.blockList.length,
          remoteBlockListCount: state.remoteBlockList.length,
          customBlockListCount: state.customBlockList.length,
          allowListCount: state.allowList.length,
          remoteLastUpdatedAt: state.remoteLastUpdatedAt,
        });
      })
      .catch((error) => {
        sendResponse({
          ok: false,
          error: error?.message || "Failed to refresh threat feed",
        });
      });
    return true;
  }

  if (message.type === "proceedToBlocked" && typeof message.targetUrl === "string") {
    const target = safeParseUrl(message.targetUrl);
    const tabId = sender.tab?.id;

    if (!target || typeof tabId !== "number") {
      sendResponse({ ok: false });
      return;
    }

    tabBypass.set(tabId, {
      hostname: target.hostname.toLowerCase(),
      expiresAt: Date.now() + BYPASS_WINDOW_MS,
    });

    chrome.tabs.update(tabId, { url: message.targetUrl }, () => {
      sendResponse({ ok: !chrome.runtime.lastError });
    });

    return true;
  }
});

chrome.tabs.onRemoved.addListener((tabId) => {
  tabInteractionTs.delete(tabId);
  tabBypass.delete(tabId);
  tabLastBlocked.delete(tabId);
});
