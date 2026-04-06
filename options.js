const STORAGE_KEYS = {
  customBlockList: "customBlockList",
  remoteBlockList: "remoteBlockList",
  remoteLastUpdatedAt: "remoteLastUpdatedAt",
  allowList: "allowList",
};

const blockListInput = document.getElementById("blockListInput");
const allowListInput = document.getElementById("allowListInput");
const remoteInfo = document.getElementById("remoteInfo");
const saveBtn = document.getElementById("saveBtn");
const saveStatus = document.getElementById("saveStatus");

function normalizePattern(input) {
  if (!input || typeof input !== "string") {
    return "";
  }

  const raw = input.trim().toLowerCase();
  if (!raw) {
    return "";
  }

  const withScheme = raw.includes("://") ? raw : `https://${raw}`;

  try {
    const parsed = new URL(withScheme);
    return parsed.hostname;
  } catch {
    return raw.replace(/^\.+/, "").replace(/\/.*/, "");
  }
}

function parseList(text) {
  const seen = new Set();
  const list = [];

  for (const line of text.split("\n")) {
    const pattern = normalizePattern(line);
    if (!pattern || seen.has(pattern)) {
      continue;
    }
    seen.add(pattern);
    list.push(pattern);
  }

  return list;
}

function serializeList(list) {
  return list.join("\n");
}

async function loadLists() {
  const result = await chrome.storage.local.get({
    [STORAGE_KEYS.customBlockList]: [],
    [STORAGE_KEYS.remoteBlockList]: [],
    [STORAGE_KEYS.remoteLastUpdatedAt]: 0,
    [STORAGE_KEYS.allowList]: [],
  });

  blockListInput.value = serializeList(result[STORAGE_KEYS.customBlockList]);
  allowListInput.value = serializeList(result[STORAGE_KEYS.allowList]);

  const remoteCount = Array.isArray(result[STORAGE_KEYS.remoteBlockList])
    ? result[STORAGE_KEYS.remoteBlockList].length
    : 0;
  const updatedAt = Number.isFinite(result[STORAGE_KEYS.remoteLastUpdatedAt])
    ? result[STORAGE_KEYS.remoteLastUpdatedAt]
    : 0;
  const updatedLabel = updatedAt ? new Date(updatedAt).toLocaleString() : "never";
  remoteInfo.textContent = `Threat feed entries: ${remoteCount} (last refresh: ${updatedLabel})`;
}

async function saveLists() {
  const customBlockList = parseList(blockListInput.value);
  const allowList = parseList(allowListInput.value);

  await chrome.storage.local.set({
    [STORAGE_KEYS.customBlockList]: customBlockList,
    [STORAGE_KEYS.allowList]: allowList,
  });

  saveStatus.textContent = "Saved";
  setTimeout(() => {
    saveStatus.textContent = "";
  }, 1500);
}

saveBtn.addEventListener("click", saveLists);

loadLists();
