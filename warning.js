const sourceEl = document.getElementById("sourceUrl");
const targetEl = document.getElementById("targetUrl");
const proceedBtn = document.getElementById("proceedBtn");
const backBtn = document.getElementById("backBtn");

const params = new URLSearchParams(window.location.search);
const source = params.get("source") || "Unknown";
const target = params.get("target") || "";

sourceEl.textContent = source;
targetEl.textContent = target || "Unknown";

proceedBtn.addEventListener("click", () => {
  if (!target) {
    return;
  }

  chrome.runtime.sendMessage({ type: "proceedToBlocked", targetUrl: target }, (response) => {
    if (!response || !response.ok) {
      window.location.href = target;
    }
  });
});

backBtn.addEventListener("click", () => {
  window.history.back();
});
