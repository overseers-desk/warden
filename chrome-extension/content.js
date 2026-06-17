// Content script for the OneDrive / SharePoint web app.
// Injects a thin bar at the top of the page showing the current folder's
// human-readable path and a short ?id=<resid>&cid=<cid> URL that addresses
// the folder by id instead of the full path.
//
// The resid is the SharePoint UniqueId of the folder, fetched from the
// page's own same-origin authenticated _api endpoint (no OAuth). Verified
// that https://onedrive.live.com/?id=<UniqueId>&cid=<CID> resolves to the
// folder for consumer (SharePoint-backed) OneDrive.
//
// OneDrive is a single-page app: navigating folders changes the URL via the
// History API without a page load, so the bar re-resolves whenever the URL
// changes (polled, since pushState in the page's main world is not visible
// from this isolated world).

"use strict";

const BAR_ID = "odpath-bar";

// --- URL / id parsing (shares the rules of convert_onedrive_url_to_path in
//     acl-manager.tcl) -------------------------------------------------------

function getDecodedId() {
  const m = location.href.match(/[?&]id=([^&]*)/);
  if (!m) return null;
  try {
    return decodeURIComponent(m[1]);
  } catch (e) {
    return m[1];
  }
}

function getCid() {
  const dec = getDecodedId();
  if (dec) {
    const m = dec.match(/^\/personal\/([^/]+)\//);
    if (m) return m[1];
  }
  const q = location.href.match(/[?&]cid=([^&]*)/);
  return q ? decodeURIComponent(q[1]) : null;
}

// The _api web root: /personal/{id}, /sites/{name}, /teams/{name}, else origin.
function getWebPrefix(serverRelative) {
  const m = serverRelative.match(/^(\/(?:personal|sites|teams)\/[^/]+)/);
  return m ? m[1] : "";
}

// Strip the document-library prefix so what remains is what the user sees.
function toDisplayPath(serverRelative) {
  let p = serverRelative.replace(/^\/personal\/[^/]+\/Documents\/?/, "");
  p = p.replace(/^\/(?:sites|teams)\/[^/]+\/(?:Shared )?Documents\/?/i, "");
  return p === "" ? "/" : p;
}

async function fetchUniqueId(serverRelative) {
  const webPrefix = getWebPrefix(serverRelative);
  // Single quotes in the path are doubled per OData string-literal escaping.
  const arg = encodeURIComponent(serverRelative).replace(/'/g, "%27%27");
  const url = `${location.origin}${webPrefix}/_api/web/GetFolderByServerRelativePath(decodedurl='${arg}')?$select=UniqueId,Name,ServerRelativeUrl`;
  const resp = await fetch(url, {
    headers: { accept: "application/json;odata=nometadata" },
    credentials: "include",
  });
  if (!resp.ok) throw new Error("API " + resp.status);
  return resp.json(); // { UniqueId, Name, ServerRelativeUrl }
}

async function computeInfo() {
  const serverRelative = getDecodedId();
  if (!serverRelative || serverRelative[0] !== "/") {
    return { ok: false };
  }
  const cid = getCid();
  const out = {
    ok: true,
    path: toDisplayPath(serverRelative),
    cid,
    shortUrl: null,
    uniqueId: null,
  };
  try {
    const data = await fetchUniqueId(serverRelative);
    out.uniqueId = data.UniqueId;
    if (cid && data.UniqueId) {
      out.shortUrl = `https://onedrive.live.com/?id=${data.UniqueId}&cid=${cid}`;
    } else if (data.UniqueId) {
      out.shortUrl = `${location.origin}/?id=${data.UniqueId}`;
      out.shortUrlBestEffort = true;
    }
  } catch (e) {
    out.shortUrlError = String(e);
  }
  return out;
}

// --- The bar ---------------------------------------------------------------

function ensureBar() {
  let bar = document.getElementById(BAR_ID);
  if (bar) return bar;

  bar = document.createElement("div");
  bar.id = BAR_ID;
  bar.style.cssText = [
    "position:fixed", "top:0", "left:0", "right:0", "z-index:2147483647",
    "display:flex", "align-items:center", "gap:10px",
    "box-sizing:border-box", "width:100%", "padding:5px 10px",
    "font:12px/1.4 system-ui,sans-serif", "color:#fff",
    "background:#1f2a37", "border-bottom:1px solid #0b1220",
    "box-shadow:0 1px 4px rgba(0,0,0,.3)",
  ].join(";");

  // Push the page down so the bar doesn't cover OneDrive's own header.
  document.documentElement.style.setProperty("padding-top", "30px", "important");

  document.documentElement.appendChild(bar);
  return bar;
}

function removeBar() {
  const bar = document.getElementById(BAR_ID);
  if (bar) bar.remove();
  document.documentElement.style.removeProperty("padding-top");
}

function makeCopyButton(getText) {
  const b = document.createElement("button");
  b.textContent = "Copy";
  b.style.cssText =
    "font:inherit;cursor:pointer;color:#fff;background:#374a5e;border:1px solid #0b1220;border-radius:3px;padding:1px 7px;white-space:nowrap;flex:none";
  b.addEventListener("click", () => {
    navigator.clipboard.writeText(getText()).then(() => {
      const old = b.textContent;
      b.textContent = "Copied";
      setTimeout(() => (b.textContent = old), 1000);
    });
  });
  return b;
}

function label(text, opts) {
  const s = document.createElement("span");
  s.textContent = text;
  s.style.cssText = "white-space:nowrap;color:#9fb3c8;flex:none";
  if (opts && opts.value) {
    s.style.color = "#fff";
    s.style.overflow = "hidden";
    s.style.textOverflow = "ellipsis";
    s.style.flex = "1 1 auto";
    s.style.minWidth = "0";
    s.title = text;
  }
  return s;
}

function render(info) {
  if (!info.ok) {
    removeBar();
    return;
  }
  const bar = ensureBar();
  bar.replaceChildren();

  bar.appendChild(label("Path:"));
  bar.appendChild(label(info.path, { value: true }));
  bar.appendChild(makeCopyButton(() => info.path));

  const sep = document.createElement("span");
  sep.style.cssText = "color:#4b5e72;flex:none";
  sep.textContent = "|";
  bar.appendChild(sep);

  if (info.shortUrl) {
    bar.appendChild(label("Short URL:"));
    const urlVal = label(info.shortUrl, { value: true });
    if (info.shortUrlBestEffort) urlVal.style.color = "#ffd479";
    bar.appendChild(urlVal);
    bar.appendChild(makeCopyButton(() => info.shortUrl));
  } else {
    bar.appendChild(
      label("Short URL unavailable" + (info.shortUrlError ? " (" + info.shortUrlError + ")" : ""))
    );
  }
}

// --- Drive it: render now and whenever the URL changes ---------------------

let lastHref = null;
let token = 0;

async function refresh() {
  const myToken = ++token; // ignore stale resolves if the URL changed again
  const info = await computeInfo();
  if (myToken !== token) return;
  render(info);
}

function tick() {
  if (location.href !== lastHref) {
    lastHref = location.href;
    refresh();
  }
}

tick();
setInterval(tick, 700);
window.addEventListener("popstate", tick);
