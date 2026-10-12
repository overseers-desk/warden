"use strict";

const msg = document.getElementById("msg");

function offer(id, value) {
  const b = document.getElementById(id);
  const v = b.querySelector(".v");
  v.textContent = v.title = value;
  b.hidden = false;
  b.addEventListener("click", () =>
    navigator.clipboard.writeText(value).then(() => window.close()));
}

async function main() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  let info;
  try {
    info = await chrome.tabs.sendMessage(tab.id, "getInfo");
  } catch (e) {
    // No content script: not a OneDrive page, or opened before the extension loaded.
    msg.textContent = "Not a OneDrive folder page (reload the tab if it is).";
    return;
  }
  if (!info || !info.ok) {
    msg.textContent = "No folder in this page's URL.";
    return;
  }
  offer("path", info.path);
  if (info.shortUrl) {
    offer("short", info.shortUrl);
    if (info.shortUrlBestEffort) {
      document.querySelector("#short .k").textContent += " (best effort: no cid)";
    }
    msg.hidden = true;
  } else {
    msg.textContent = "Short URL unavailable" + (info.shortUrlError ? " (" + info.shortUrlError + ")" : "");
  }
}

main();
