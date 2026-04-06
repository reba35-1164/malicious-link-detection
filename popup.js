const STORAGE_KEY = "extensionEnabled";

const enabledToggle = document.getElementById("enabledToggle");
const statusText = document.getElementById("statusText");
const redirectCountText = document.getElementById("redirectCountText");
const listCountText = document.getElementById("listCountText");
const allowListCountText = document.getElementById("allowListCountText");
const blockedRedirectCountText = document.getElementById("blockedRedirectCountText");
const remoteUpdatedText = document.getElementById("remoteUpdatedText");
const refreshFeedBtn = document.getElementById("refreshFeedBtn");
const manageListsBtn = document.getElementById("manageListsBtn");

function updateUI(enabled) {
  enabledToggle.checked = enabled;
  statusText.textContent = enabled ? "Enabled" : "Disabled";
  statusText.classList.toggle("is-disabled", !enabled);
}

function formatRefreshTime(timestamp) {
  if (!timestamp) {
    return "never";
  }

  const date = new Date(timestamp);
  if (Number.isNaN(date.getTime())) {
    return "unknown";
  }

  return date.toLocaleString();
}

function setRefreshButtonState(loading) {
  refreshFeedBtn.disabled = loading;
  refreshFeedBtn.textContent = loading ? "Refreshing..." : "Refresh feed";
}

async function loadState() {
  const result = await chrome.storage.local.get({ [STORAGE_KEY]: true });
  const enabled = result[STORAGE_KEY] !== false;
  updateUI(enabled);

  chrome.runtime.sendMessage({ type: "getPopupState" }, (state) => {
    const redirectCount = state?.redirectCount ?? 0;
    const blockedRedirectCount = state?.blockedRedirectCount ?? 0;
    const blockListCount = state?.blockListCount ?? 0;
    const allowListCount = state?.allowListCount ?? 0;
    const remoteLastUpdatedAt = state?.remoteLastUpdatedAt ?? 0;

    redirectCountText.textContent = String(redirectCount);
    blockedRedirectCountText.textContent = String(blockedRedirectCount);
    listCountText.textContent = String(blockListCount);
    allowListCountText.textContent = String(allowListCount);
    remoteUpdatedText.textContent = `Last threat feed refresh: ${formatRefreshTime(remoteLastUpdatedAt)}`;
  });
}

enabledToggle.addEventListener("change", async () => {
  const enabled = enabledToggle.checked;
  await chrome.storage.local.set({ [STORAGE_KEY]: enabled });
  updateUI(enabled);
});

manageListsBtn.addEventListener("click", () => {
  chrome.runtime.openOptionsPage();
});

refreshFeedBtn.addEventListener("click", () => {
  setRefreshButtonState(true);

  chrome.runtime.sendMessage({ type: "refreshThreatFeed" }, async (response) => {
    setRefreshButtonState(false);

    if (!response?.ok) {
      const message = response?.error ? String(response.error) : "Unknown error";
      remoteUpdatedText.textContent = `Last threat feed refresh: failed (${message})`;
      return;
    }

    await loadState();
  });
});

loadState();
