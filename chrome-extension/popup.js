"use strict";

function el(tag, props, children) {
  const e = document.createElement(tag);
  Object.assign(e, props || {});
  for (const c of children || []) e.append(c);
  return e;
}

function field(label, value, copyable) {
  const valDiv = el("div", { className: "value", textContent: value });
  const inner = copyable
    ? el("div", { className: "row" }, [
        valDiv,
        el("button", {
          textContent: "Copy",
          onclick: () => navigator.clipboard.writeText(value),
        }),
      ])
    : valDiv;
  return el("div", { className: "field" }, [
    el("div", { className: "label", textContent: label }),
    inner,
  ]);
}

async function main() {
  const content = document.getElementById("content");
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab || !/^https:\/\/(onedrive\.live\.com|[^/]+\.sharepoint\.com)\//.test(tab.url || "")) {
    content.textContent = "Not a OneDrive/SharePoint tab.";
    return;
  }
  let info;
  try {
    info = await chrome.tabs.sendMessage(tab.id, { type: "GET_INFO" });
  } catch (e) {
    content.textContent =
      "Could not reach the page. Reload the OneDrive tab and try again.";
    return;
  }
  content.textContent = "";
  if (!info || !info.ok) {
    content.append(
      el("div", { className: "err", textContent: (info && info.reason) || "No data." })
    );
    return;
  }
  content.append(field("Path", info.path, true));
  if (info.shortUrl) {
    content.append(field("Short URL (by id)", info.shortUrl, true));
    if (info.shortUrlNote) {
      content.append(el("div", { className: "muted", textContent: info.shortUrlNote }));
    }
  } else {
    content.append(
      el("div", { className: "err", textContent: "Short URL unavailable: " + (info.shortUrlError || "no id") })
    );
  }
  if (info.uniqueId) content.append(field("Folder id (resid)", info.uniqueId, true));
}

main();
